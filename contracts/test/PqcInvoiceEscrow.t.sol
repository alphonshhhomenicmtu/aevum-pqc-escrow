// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqcInvoiceEscrow} from "../src/PqcInvoiceEscrow.sol";

interface Vm {
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert(bytes4 revertSelector) external;
}

contract MockTUSD8 {
    string public constant name = "tUSD8";
    string public constant version = "2";
    uint8 public constant decimals = 6;

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    error AuthorizationUsed();
    error InvalidSigner();
    error ExpiredAuthorization();

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "INSUFFICIENT");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "INSUFFICIENT");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp <= validAfter || block.timestamp >= validBefore) revert ExpiredAuthorization();
        if (authorizationState[from][nonce]) revert AuthorizationUsed();

        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != from) revert InvalidSigner();

        authorizationState[from][nonce] = true;
        require(balanceOf[from] >= value, "INSUFFICIENT");
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
}

contract PqcInvoiceEscrowTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockTUSD8 private tusd8;
    PqcInvoiceEscrow private escrow;

    uint256 private constant PAYER_PK = 0xA11CE;
    address private payer;
    address private merchant = address(0xBEEF);

    function setUp() public {
        payer = vm.addr(PAYER_PK);
        tusd8 = new MockTUSD8();
        escrow = new PqcInvoiceEscrow(address(tusd8));
        tusd8.mint(payer, 100_000_000); // 100 tUSD8 (6 decimals)
    }

    function _makeLamport(bytes32 seed)
        internal
        pure
        returns (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1)
    {
        for (uint256 i = 0; i < 256; i++) {
            sk0[i] = sha256(abi.encodePacked(seed, uint16(i), uint8(0)));
            sk1[i] = sha256(abi.encodePacked(seed, uint16(i), uint8(1)));
            pk0[i] = sha256(abi.encodePacked(sk0[i]));
            pk1[i] = sha256(abi.encodePacked(sk1[i]));
        }
    }

    function _signLamport(bytes32 msgDigest, bytes32[256] memory sk0, bytes32[256] memory sk1)
        internal
        pure
        returns (bytes32[256] memory preimages)
    {
        uint256 m = uint256(msgDigest);
        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (m >> (255 - i)) & 1;
            preimages[i] = bit == 1 ? sk1[i] : sk0[i];
        }
    }

    function _signReceiveAuth(
        uint256 pk,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        address from = vm.addr(pk);
        bytes32 structHash = keccak256(
            abi.encode(tusd8.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, validAfter, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", tusd8.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(pk, digest);
    }

    function test_FundAndReleaseWithValidLamportProof() public {
        (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1) =
            _makeLamport(keccak256("seed-1"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-001");

        vm.prank(payer);
        tusd8.approve(address(escrow), 5_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 5_000_000, uint64(block.timestamp + 1 days), pubHash);

        bytes32 msgDigest = escrow.invoiceMessageDigest(invoiceId);
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);

        vm.prank(merchant);
        escrow.releaseWithLamportProof(invoiceId, preimages, pk0, pk1);

        assert(tusd8.balanceOf(merchant) == 5_000_000);
        assert(escrow.getInvoice(invoiceId).status == PqcInvoiceEscrow.Status.Released);
    }

    function test_FundWithAuthorizationEIP3009Gasless() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-2"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-gasless");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = escrow.authorizationNonce(invoiceId, merchant, expiry, pubHash);

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(
            PAYER_PK, address(escrow), 10_000_000, 0, validBefore, nonce
        );

        // Relayer submits without payer paying native tQDAY gas. The nonce already binds merchant, expiry, and key.
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 10_000_000, expiry, pubHash, 0, validBefore, v, r, s
        );

        assert(tusd8.balanceOf(address(escrow)) == 10_000_000);
        assert(escrow.getInvoice(invoiceId).payer == payer);
    }

    function test_RevertWhen_ReplayInvoiceOrAuthorization() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-3"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-replay");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = escrow.authorizationNonce(invoiceId, merchant, expiry, pubHash);

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(
            PAYER_PK, address(escrow), 1_000_000, 0, validBefore, nonce
        );

        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 1_000_000, expiry, pubHash, 0, validBefore, v, r, s
        );

        vm.expectRevert(PqcInvoiceEscrow.InvoiceAlreadyExists.selector);
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 1_000_000, expiry, pubHash, 0, validBefore, v, r, s
        );
    }

    function test_RevertWhen_RelayerHijacksEIP3009Terms() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-hijack"));
        bytes32 honestHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-hijack");
        uint64 honestExpiry = uint64(block.timestamp + 1 days);
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = escrow.authorizationNonce(invoiceId, merchant, honestExpiry, honestHash);

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveAuth(PAYER_PK, address(escrow), 4_000_000, 0, validBefore, nonce);

        address attackerMerchant = address(0xBAD);
        uint64 swappedExpiry = uint64(block.timestamp + 30 days);
        bytes32 swappedPk = keccak256("attacker-pk");

        vm.expectRevert(MockTUSD8.InvalidSigner.selector);
        escrow.fundWithAuthorization(
            invoiceId, payer, attackerMerchant, 4_000_000, honestExpiry, honestHash, 0, validBefore, v, r, s
        );

        vm.expectRevert(MockTUSD8.InvalidSigner.selector);
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 4_000_000, swappedExpiry, honestHash, 0, validBefore, v, r, s
        );

        vm.expectRevert(MockTUSD8.InvalidSigner.selector);
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 4_000_000, honestExpiry, swappedPk, 0, validBefore, v, r, s
        );

        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 4_000_000, honestExpiry, honestHash, 0, validBefore, v, r, s
        );
        PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(invoiceId);
        assert(inv.merchant == merchant);
        assert(inv.expiresAt == honestExpiry);
        assert(inv.pqcPubKeyHash == honestHash);
        assert(tusd8.balanceOf(address(escrow)) == 4_000_000);
    }

    function test_RevertWhen_TamperedLamportPreimage() public {
        (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1) =
            _makeLamport(keccak256("seed-4"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-tamper");

        vm.prank(payer);
        tusd8.approve(address(escrow), 2_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 2_000_000, uint64(block.timestamp + 1 days), pubHash);

        bytes32 msgDigest = escrow.invoiceMessageDigest(invoiceId);
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);
        preimages[0] = bytes32(uint256(preimages[0]) ^ 1); // flip 1 bit

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidLamportProof.selector);
        escrow.releaseWithLamportProof(invoiceId, preimages, pk0, pk1);
    }

    function test_RevertWhen_WrongPubKeyHash() public {
        (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1) =
            _makeLamport(keccak256("seed-5"));
        bytes32 invoiceId = keccak256("inv-badpk");

        vm.prank(payer);
        tusd8.approve(address(escrow), 2_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 2_000_000, uint64(block.timestamp + 1 days), keccak256("other-pk"));

        bytes32 msgDigest = escrow.invoiceMessageDigest(invoiceId);
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidLamportPubKeyHash.selector);
        escrow.releaseWithLamportProof(invoiceId, preimages, pk0, pk1);
    }

    function test_RevertWhen_LamportProofNotBoundToInvoice() public {
        (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1) =
            _makeLamport(keccak256("seed-unbound"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-unbound");

        vm.prank(payer);
        tusd8.approve(address(escrow), 2_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 2_000_000, uint64(block.timestamp + 1 days), pubHash);

        PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(invoiceId);
        bytes32 wrongDigest = sha256(
            abi.encode(invoiceId, inv.amount + 1, inv.payer, inv.merchant, block.chainid, address(escrow))
        );
        bytes32[256] memory preimages = _signLamport(wrongDigest, sk0, sk1);

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidLamportProof.selector);
        escrow.releaseWithLamportProof(invoiceId, preimages, pk0, pk1);
        assert(escrow.getInvoice(invoiceId).status == PqcInvoiceEscrow.Status.Funded);
    }

    function test_RefundExpired() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-6"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-expire");
        uint64 expiry = uint64(block.timestamp + 1 hours);

        vm.prank(payer);
        tusd8.approve(address(escrow), 3_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 3_000_000, expiry, pubHash);

        vm.warp(expiry + 1);
        escrow.refundExpired(invoiceId);
        assert(tusd8.balanceOf(payer) == 100_000_000);
        assert(escrow.getInvoice(invoiceId).status == PqcInvoiceEscrow.Status.Refunded);
    }

    function test_RevertWhen_RefundBeforeExpiry() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-7"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-not-expired");

        vm.prank(payer);
        tusd8.approve(address(escrow), 3_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 3_000_000, uint64(block.timestamp + 1 hours), pubHash);

        vm.expectRevert(PqcInvoiceEscrow.NotExpired.selector);
        escrow.refundExpired(invoiceId);
    }

    function test_RevertWhen_UnauthorizedRelease() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-8"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-unauth");

        vm.prank(payer);
        tusd8.approve(address(escrow), 3_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 3_000_000, uint64(block.timestamp + 1 hours), pubHash);

        vm.prank(payer);
        vm.expectRevert(PqcInvoiceEscrow.NotMerchant.selector);
        escrow.release(invoiceId, keccak256("sig"));
    }

    function test_RevertWhen_ZeroAmountOrZeroAddress() public {
        bytes32 pubHash = keccak256("pk-zero");
        vm.prank(payer);
        vm.expectRevert(PqcInvoiceEscrow.ZeroAmount.selector);
        escrow.fund(keccak256("inv-zero-amt"), merchant, 0, uint64(block.timestamp + 1 hours), pubHash);

        vm.prank(payer);
        vm.expectRevert(PqcInvoiceEscrow.ZeroAddress.selector);
        escrow.fund(keccak256("inv-zero-addr"), address(0), 1_000_000, uint64(block.timestamp + 1 hours), pubHash);
    }

    function test_RevertWhen_ZeroSigDigest() public {
        bytes32 pubHash = keccak256("pk-zerosig");
        bytes32 invoiceId = keccak256("inv-zerosig");

        vm.prank(payer);
        tusd8.approve(address(escrow), 1_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 1_000_000, uint64(block.timestamp + 1 hours), pubHash);

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.ZeroCommitment.selector);
        escrow.release(invoiceId, bytes32(0));
    }

    function test_RevertWhen_DoubleReleaseOrDoubleRefund() public {
        bytes32 pubHash = keccak256("pk-double");
        bytes32 invoiceId1 = keccak256("inv-double-rel");
        bytes32 invoiceId2 = keccak256("inv-double-ref");
        uint64 expiry = uint64(block.timestamp + 1 hours);

        vm.prank(payer);
        tusd8.approve(address(escrow), 2_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId1, merchant, 1_000_000, expiry, pubHash);
        vm.prank(payer);
        escrow.fund(invoiceId2, merchant, 1_000_000, expiry, pubHash);

        vm.prank(merchant);
        escrow.release(invoiceId1, keccak256("sig-1"));
        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidStatus.selector);
        escrow.release(invoiceId1, keccak256("sig-1"));

        vm.warp(expiry + 1);
        escrow.refundExpired(invoiceId2);
        vm.expectRevert(PqcInvoiceEscrow.InvalidStatus.selector);
        escrow.refundExpired(invoiceId2);
    }

    function test_RevertWhen_ReleaseAfterRefund() public {
        bytes32 pubHash = keccak256("pk-rel-after-ref");
        bytes32 invoiceId = keccak256("inv-rel-after-ref");
        uint64 expiry = uint64(block.timestamp + 1 hours);

        vm.prank(payer);
        tusd8.approve(address(escrow), 1_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 1_000_000, expiry, pubHash);

        vm.warp(expiry + 1);
        escrow.refundExpired(invoiceId);

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidStatus.selector);
        escrow.release(invoiceId, keccak256("late-sig"));
    }
}
