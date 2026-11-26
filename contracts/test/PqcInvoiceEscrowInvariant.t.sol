// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqcInvoiceEscrow} from "../src/PqcInvoiceEscrow.sol";
import {MockTUSD8, Vm} from "./PqcInvoiceEscrow.t.sol";

contract PqcInvoiceEscrowHandler {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockTUSD8 public immutable token;
    PqcInvoiceEscrow public immutable escrow;

    uint256 private constant PAYER_PK = 0xA11CE;
    address public immutable eip3009Payer;

    address[3] private _payers = [address(0x1001), address(0x1002), address(0x1003)];
    address[3] private _merchants = [address(0x2001), address(0x2002), address(0x2003)];
    address private constant ATTACKER = address(0xBAD);

    bytes32[256] private _sk0;
    bytes32[256] private _sk1;
    bytes32[256] private _pk0;
    bytes32[256] private _pk1;
    bytes32 public immutable lamportPubKeyHash;

    bytes32[] public invoiceIds;
    mapping(bytes32 => uint256) public ghostAmount;
    mapping(bytes32 => uint8) public expectedTerminal; // 0 = Funded, 1 = Released, 2 = Refunded
    mapping(bytes32 => bool) public usesLamportProof;

    uint256 public ghostActiveEscrowSum;
    uint256 public ghostTotalFunded;
    uint256 public ghostTotalReleased;
    uint256 public ghostTotalRefunded;
    uint256 public ghostViolations;
    uint256 private _nonceCounter;

    constructor(MockTUSD8 token_, PqcInvoiceEscrow escrow_) {
        token = token_;
        escrow = escrow_;
        eip3009Payer = vm.addr(PAYER_PK);

        bytes32 seed = keccak256("aevum-invariant-lamport-seed");
        for (uint256 i = 0; i < 256; i++) {
            _sk0[i] = sha256(abi.encodePacked(seed, uint16(i), uint8(0)));
            _sk1[i] = sha256(abi.encodePacked(seed, uint16(i), uint8(1)));
            _pk0[i] = sha256(abi.encodePacked(_sk0[i]));
            _pk1[i] = sha256(abi.encodePacked(_sk1[i]));
        }
        lamportPubKeyHash = escrow_.computeLamportPubKeyHash(_pk0, _pk1);
    }

    function invoiceCount() external view returns (uint256) {
        return invoiceIds.length;
    }

    function fundStandard(uint8 payerIdx, uint8 merchantIdx, uint96 amountRaw, uint32 ttlRaw, bool withLamport)
        external
    {
        address payer = _payers[payerIdx % _payers.length];
        address merchant = _merchants[merchantIdx % _merchants.length];
        uint256 amount = (uint256(amountRaw) % 50_000_000) + 1;
        uint64 expiry = uint64(block.timestamp + (uint256(ttlRaw) % 7 days) + 60);

        _nonceCounter++;
        bytes32 invoiceId = keccak256(abi.encodePacked("std", _nonceCounter, payer, merchant));
        bytes32 commitment = withLamport ? lamportPubKeyHash : keccak256(abi.encodePacked("pqc", invoiceId));

        token.mint(payer, amount);
        vm.prank(payer);
        token.approve(address(escrow), amount);
        vm.prank(payer);
        escrow.fund(invoiceId, merchant, amount, expiry, commitment);

        invoiceIds.push(invoiceId);
        ghostAmount[invoiceId] = amount;
        expectedTerminal[invoiceId] = 0;
        usesLamportProof[invoiceId] = withLamport;
        ghostActiveEscrowSum += amount;
        ghostTotalFunded += amount;
    }

    function fundGaslessEIP3009(uint8 merchantIdx, uint96 amountRaw, uint32 ttlRaw) external {
        address merchant = _merchants[merchantIdx % _merchants.length];
        uint256 amount = (uint256(amountRaw) % 50_000_000) + 1;
        uint64 expiry = uint64(block.timestamp + (uint256(ttlRaw) % 7 days) + 60);

        _nonceCounter++;
        bytes32 invoiceId = keccak256(abi.encodePacked("eip3009", _nonceCounter, merchant));
        bytes32 authNonce = escrow.authorizationNonce(invoiceId);
        uint256 validBefore = block.timestamp + 1 hours;

        bytes32 structHash = keccak256(
            abi.encode(
                token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                eip3009Payer,
                address(escrow),
                amount,
                uint256(0),
                validBefore,
                authNonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, digest);

        token.mint(eip3009Payer, amount);
        escrow.fundWithAuthorization(
            invoiceId, eip3009Payer, merchant, amount, expiry, lamportPubKeyHash, 0, validBefore, v, r, s
        );

        invoiceIds.push(invoiceId);
        ghostAmount[invoiceId] = amount;
        expectedTerminal[invoiceId] = 0;
        usesLamportProof[invoiceId] = true;
        ghostActiveEscrowSum += amount;
        ghostTotalFunded += amount;
    }

    function releaseInvoice(uint256 idxSeed) external {
        if (invoiceIds.length == 0) return;
        bytes32 invoiceId = invoiceIds[idxSeed % invoiceIds.length];
        PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(invoiceId);
        if (inv.status != PqcInvoiceEscrow.Status.Funded) return;

        if (usesLamportProof[invoiceId]) {
            bytes32 msgDigest = sha256(abi.encodePacked("DELIVERED:", invoiceId));
            bytes32[256] memory preimages = _signLamport(msgDigest);
            vm.prank(inv.merchant);
            escrow.releaseWithLamportProof(invoiceId, msgDigest, preimages, _pk0, _pk1);
        } else {
            vm.prank(inv.merchant);
            escrow.release(invoiceId, keccak256(abi.encodePacked("sig", invoiceId)));
        }

        expectedTerminal[invoiceId] = 1;
        ghostActiveEscrowSum -= inv.amount;
        ghostTotalReleased += inv.amount;
    }

    function refundExpiredInvoice(uint256 idxSeed) external {
        if (invoiceIds.length == 0) return;
        bytes32 invoiceId = invoiceIds[idxSeed % invoiceIds.length];
        PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(invoiceId);
        if (inv.status != PqcInvoiceEscrow.Status.Funded) return;

        if (block.timestamp < inv.expiresAt) {
            vm.warp(uint256(inv.expiresAt) + 1);
        }

        escrow.refundExpired(invoiceId);
        expectedTerminal[invoiceId] = 2;
        ghostActiveEscrowSum -= inv.amount;
        ghostTotalRefunded += inv.amount;
    }

    function warpForward(uint32 deltaRaw) external {
        uint256 delta = (uint256(deltaRaw) % 2 days) + 1;
        vm.warp(block.timestamp + delta);
    }

    function probeAdversarialInvariants(uint256 idxSeed) external {
        if (invoiceIds.length == 0) return;
        bytes32 invoiceId = invoiceIds[idxSeed % invoiceIds.length];
        PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(invoiceId);

        // 1. Non-merchant cannot release
        if (inv.status == PqcInvoiceEscrow.Status.Funded) {
            vm.prank(ATTACKER);
            try escrow.release(invoiceId, keccak256("forged")) {
                ghostViolations++;
            } catch {}

            // 2. Non-expired refund must revert
            if (block.timestamp < inv.expiresAt) {
                vm.prank(ATTACKER);
                try escrow.refundExpired(invoiceId) {
                    ghostViolations++;
                } catch {}
            }

            // 3. Tampered Lamport proof (1-bit flip) must revert
            if (usesLamportProof[invoiceId]) {
                bytes32 msgDigest = sha256(abi.encodePacked("DELIVERED:", invoiceId));
                bytes32[256] memory badPreimages = _signLamport(msgDigest);
                badPreimages[0] = bytes32(uint256(badPreimages[0]) ^ 1);
                vm.prank(inv.merchant);
                try escrow.releaseWithLamportProof(invoiceId, msgDigest, badPreimages, _pk0, _pk1) {
                    ghostViolations++;
                } catch {}
            }
        } else {
            // 4. Terminal states cannot be double-released, double-refunded, or released-after-refund
            vm.prank(inv.merchant);
            try escrow.release(invoiceId, keccak256("replay")) {
                ghostViolations++;
            } catch {}

            try escrow.refundExpired(invoiceId) {
                ghostViolations++;
            } catch {}
        }

        // 5. Duplicate invoiceId replay must revert
        token.mint(ATTACKER, 1_000_000);
        vm.prank(ATTACKER);
        token.approve(address(escrow), 1_000_000);
        vm.prank(ATTACKER);
        try escrow.fund(invoiceId, ATTACKER, 1_000_000, uint64(block.timestamp + 100), keccak256("dup")) {
            ghostViolations++;
        } catch {}
    }

    function _signLamport(bytes32 msgDigest) internal view returns (bytes32[256] memory preimages) {
        uint256 m = uint256(msgDigest);
        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (m >> (255 - i)) & 1;
            preimages[i] = bit == 1 ? _sk1[i] : _sk0[i];
        }
    }
}

contract PqcInvoiceEscrowInvariantTest {
    MockTUSD8 private tusd8;
    PqcInvoiceEscrow private escrow;
    PqcInvoiceEscrowHandler private handler;
    address[] private _targetedContracts;

    function setUp() public {
        tusd8 = new MockTUSD8();
        escrow = new PqcInvoiceEscrow(address(tusd8));
        handler = new PqcInvoiceEscrowHandler(tusd8, escrow);
        _targetedContracts.push(address(handler));
    }

    function targetContracts() public view returns (address[] memory) {
        return _targetedContracts;
    }

    /// @notice Conservation of escrow accounting: contract balance >= sum of all active escrows at all times.
    function invariant_escrowAccountingConservation() public view {
        uint256 contractBalance = tusd8.balanceOf(address(escrow));
        assert(contractBalance >= handler.ghostActiveEscrowSum());
        assert(
            handler.ghostTotalFunded()
                == handler.ghostTotalReleased() + handler.ghostTotalRefunded() + handler.ghostActiveEscrowSum()
        );
    }

    /// @notice No double-release, double-refund, release-after-refund, early-refund, or tampered Lamport bypass.
    function invariant_noDoubleSettlementOrAdversarialBypass() public view {
        assert(handler.ghostViolations() == 0);

        uint256 count = handler.invoiceCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 id = handler.invoiceIds(i);
            PqcInvoiceEscrow.Invoice memory inv = escrow.getInvoice(id);
            uint8 expected = handler.expectedTerminal(id);
            if (expected == 0) {
                assert(inv.status == PqcInvoiceEscrow.Status.Funded);
                assert(inv.amount == handler.ghostAmount(id));
                assert(inv.amount > 0);
                assert(inv.pqcPubKeyHash != bytes32(0));
            } else if (expected == 1) {
                assert(inv.status == PqcInvoiceEscrow.Status.Released);
            } else if (expected == 2) {
                assert(inv.status == PqcInvoiceEscrow.Status.Refunded);
            }
        }
    }
}
