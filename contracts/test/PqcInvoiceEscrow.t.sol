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

        bytes32 msgDigest = sha256("DELIVERED:inv-001");
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);

        vm.prank(merchant);
        escrow.releaseWithLamportProof(invoiceId, msgDigest, preimages, pk0, pk1);

        assert(tusd8.balanceOf(merchant) == 5_000_000);
        assert(escrow.getInvoice(invoiceId).status == PqcInvoiceEscrow.Status.Released);
    }

    function test_FundWithAuthorizationEIP3009Gasless() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-2"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-gasless");
        bytes32 nonce = escrow.authorizationNonce(invoiceId);

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(
            PAYER_PK, address(escrow), 10_000_000, 0, block.timestamp + 1 hours, nonce
        );

        // Relayer submits without payer paying native tQDAY gas
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 10_000_000, uint64(block.timestamp + 1 days), pubHash, 0, block.timestamp + 1 hours, v, r, s
        );

        assert(tusd8.balanceOf(address(escrow)) == 10_000_000);
        assert(escrow.getInvoice(invoiceId).payer == payer);
    }

    function test_RevertWhen_ReplayInvoiceOrAuthorization() public {
        (, , bytes32[256] memory pk0, bytes32[256] memory pk1) = _makeLamport(keccak256("seed-3"));
        bytes32 pubHash = escrow.computeLamportPubKeyHash(pk0, pk1);
        bytes32 invoiceId = keccak256("inv-replay");
        bytes32 nonce = escrow.authorizationNonce(invoiceId);

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(
            PAYER_PK, address(escrow), 1_000_000, 0, block.timestamp + 1 hours, nonce
        );

        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 1_000_000, uint64(block.timestamp + 1 days), pubHash, 0, block.timestamp + 1 hours, v, r, s
        );

        vm.expectRevert(PqcInvoiceEscrow.InvoiceAlreadyExists.selector);
        escrow.fundWithAuthorization(
            invoiceId, payer, merchant, 1_000_000, uint64(block.timestamp + 1 days), pubHash, 0, block.timestamp + 1 hours, v, r, s
        );
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

        bytes32 msgDigest = sha256("DELIVERED:inv-tamper");
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);
        preimages[0] = bytes32(uint256(preimages[0]) ^ 1); // flip 1 bit

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidLamportProof.selector);
        escrow.releaseWithLamportProof(invoiceId, msgDigest, preimages, pk0, pk1);
    }

    function test_RevertWhen_WrongPubKeyHash() public {
        (bytes32[256] memory sk0, bytes32[256] memory sk1, bytes32[256] memory pk0, bytes32[256] memory pk1) =
            _makeLamport(keccak256("seed-5"));
        bytes32 invoiceId = keccak256("inv-badpk");

        vm.prank(payer);
        tusd8.approve(address(escrow), 2_000_000);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, 2_000_000, uint64(block.timestamp + 1 days), keccak256("other-pk"));

        bytes32 msgDigest = sha256("DELIVERED:inv-badpk");
        bytes32[256] memory preimages = _signLamport(msgDigest, sk0, sk1);

        vm.prank(merchant);
        vm.expectRevert(PqcInvoiceEscrow.InvalidLamportPubKeyHash.selector);
        escrow.releaseWithLamportProof(invoiceId, msgDigest, preimages, pk0, pk1);
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
}
