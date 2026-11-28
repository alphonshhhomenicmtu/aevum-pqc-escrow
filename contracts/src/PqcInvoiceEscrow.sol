// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 interface for tUSD8 on QDay Aevum Testnet (Shanghai EVM).
interface IERC20Minimal {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @notice EIP-3009 signed transfer interface implemented by tUSD8.
interface IERC3009Minimal {
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
    ) external;
}

/// @title PqcInvoiceEscrow
/// @notice Post-Quantum verifiable tUSD8 escrow supporting standard and gasless EIP-3009 settlement.
contract PqcInvoiceEscrow {
    enum Status {
        None,
        Funded,
        Released,
        Refunded
    }

    struct Invoice {
        address payer;
        address merchant;
        uint256 amount;
        uint64 expiresAt;
        bytes32 pqcPubKeyHash;
        bytes32 pqcSigDigest;
        Status status;
    }

    IERC20Minimal public immutable token;

    mapping(bytes32 invoiceId => Invoice) private _invoices;

    event InvoiceFunded(
        bytes32 indexed invoiceId,
        address indexed payer,
        address indexed merchant,
        uint256 amount,
        bytes32 pqcPubKeyHash,
        uint64 expiresAt
    );
    event InvoiceReleased(bytes32 indexed invoiceId, bytes32 pqcSigDigest);
    event InvoiceRefunded(bytes32 indexed invoiceId, address indexed payer, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error ZeroCommitment();
    error InvoiceAlreadyExists();
    error InvalidStatus();
    error NotMerchant();
    error NotExpired();
    error InvalidLamportPubKeyHash();
    error InvalidLamportProof();
    error TransferFailed();

    constructor(address token_) {
        if (token_ == address(0)) revert ZeroAddress();
        token = IERC20Minimal(token_);
    }

    function fund(
        bytes32 invoiceId,
        address merchant,
        uint256 amount,
        uint64 expiresAt,
        bytes32 pqcPubKeyHash
    ) external {
        _createInvoice(invoiceId, msg.sender, merchant, amount, expiresAt, pqcPubKeyHash);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
    }

    function fundWithAuthorization(
        bytes32 invoiceId,
        address from,
        address merchant,
        uint256 amount,
        uint64 expiresAt,
        bytes32 pqcPubKeyHash,
        uint256 validAfter,
        uint256 validBefore,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // EIP-3009 signs only from/to/value/window/nonce. Bind the relayer-chosen
        // terms into that nonce so merchant, expiry, and Lamport key cannot be swapped.
        bytes32 nonce = authorizationNonce(invoiceId, merchant, expiresAt, pqcPubKeyHash);
        _createInvoice(invoiceId, from, merchant, amount, expiresAt, pqcPubKeyHash);
        IERC3009Minimal(address(token)).receiveWithAuthorization(
            from, address(this), amount, validAfter, validBefore, nonce, v, r, s
        );
    }

    function release(bytes32 invoiceId, bytes32 pqcSigDigest) external {
        Invoice storage inv = _invoices[invoiceId];
        if (inv.status != Status.Funded) revert InvalidStatus();
        if (msg.sender != inv.merchant) revert NotMerchant();
        if (pqcSigDigest == bytes32(0)) revert ZeroCommitment();

        inv.pqcSigDigest = pqcSigDigest;
        inv.status = Status.Released;
        emit InvoiceReleased(invoiceId, pqcSigDigest);

        if (!token.transfer(inv.merchant, inv.amount)) revert TransferFailed();
    }

    /// @notice Release escrow when the Lamport proof signs this invoice's on-chain commitment.
    function releaseWithLamportProof(
        bytes32 invoiceId,
        bytes32[256] calldata preimages,
        bytes32[256] calldata pk0,
        bytes32[256] calldata pk1
    ) external {
        Invoice storage inv = _invoices[invoiceId];
        if (inv.status != Status.Funded) revert InvalidStatus();
        if (msg.sender != inv.merchant) revert NotMerchant();

        bytes32 pubKeyHash = computeLamportPubKeyHash(pk0, pk1);
        if (pubKeyHash != inv.pqcPubKeyHash) revert InvalidLamportPubKeyHash();

        bytes32 messageDigest = invoiceMessageDigest(invoiceId);
        bytes32 sigDigest = verifyLamportProof(messageDigest, preimages, pk0, pk1);
        inv.pqcSigDigest = sigDigest;
        inv.status = Status.Released;
        emit InvoiceReleased(invoiceId, sigDigest);

        if (!token.transfer(inv.merchant, inv.amount)) revert TransferFailed();
    }

    function refundExpired(bytes32 invoiceId) external {
        Invoice storage inv = _invoices[invoiceId];
        if (inv.status != Status.Funded) revert InvalidStatus();
        if (block.timestamp < inv.expiresAt) revert NotExpired();

        inv.status = Status.Refunded;
        emit InvoiceRefunded(invoiceId, inv.payer, inv.amount);

        if (!token.transfer(inv.payer, inv.amount)) revert TransferFailed();
    }

    function computeLamportPubKeyHash(bytes32[256] calldata pk0, bytes32[256] calldata pk1)
        public
        pure
        returns (bytes32)
    {
        bytes memory buf = new bytes(256 * 64);
        for (uint256 i = 0; i < 256; i++) {
            bytes32 p0 = pk0[i];
            bytes32 p1 = pk1[i];
            assembly {
                let ptr := add(add(buf, 32), mul(i, 64))
                mstore(ptr, p0)
                mstore(add(ptr, 32), p1)
            }
        }
        return sha256(buf);
    }

    function verifyLamportProof(
        bytes32 messageDigest,
        bytes32[256] calldata preimages,
        bytes32[256] calldata pk0,
        bytes32[256] calldata pk1
    ) public pure returns (bytes32) {
        uint256 msgUint = uint256(messageDigest);
        bytes memory sigBuf = new bytes(32 + 256 * 32);
        assembly {
            mstore(add(sigBuf, 32), messageDigest)
        }
        for (uint256 i = 0; i < 256; i++) {
            uint256 bit = (msgUint >> (255 - i)) & 1;
            bytes32 preimage = preimages[i];
            bytes32 expectedPk = bit == 1 ? pk1[i] : pk0[i];
            if (sha256(abi.encodePacked(preimage)) != expectedPk) revert InvalidLamportProof();
            assembly {
                mstore(add(add(sigBuf, 64), mul(i, 32)), preimage)
            }
        }
        return sha256(sigBuf);
    }

    /// @notice EIP-3009 nonce bound to this escrow, the invoice, and the terms a relayer could otherwise substitute.
    function authorizationNonce(
        bytes32 invoiceId,
        address merchant,
        uint64 expiresAt,
        bytes32 pqcPubKeyHash
    ) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), invoiceId, merchant, expiresAt, pqcPubKeyHash));
    }

    /// @notice ABI encoding of the stored invoice. Lamport signatures must cover these exact bytes.
    function invoiceCommitment(bytes32 invoiceId) public view returns (bytes memory) {
        Invoice storage inv = _invoices[invoiceId];
        return abi.encode(invoiceId, inv.amount, inv.payer, inv.merchant, block.chainid, address(this));
    }

    /// @notice sha256 of `invoiceCommitment`. This is the only digest `releaseWithLamportProof` accepts.
    function invoiceMessageDigest(bytes32 invoiceId) public view returns (bytes32) {
        return sha256(invoiceCommitment(invoiceId));
    }

    function getInvoice(bytes32 invoiceId) external view returns (Invoice memory) {
        return _invoices[invoiceId];
    }

    function _createInvoice(
        bytes32 invoiceId,
        address payer,
        address merchant,
        uint256 amount,
        uint64 expiresAt,
        bytes32 pqcPubKeyHash
    ) private {
        if (payer == address(0) || merchant == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (pqcPubKeyHash == bytes32(0)) revert ZeroCommitment();
        if (_invoices[invoiceId].status != Status.None) revert InvoiceAlreadyExists();

        _invoices[invoiceId] = Invoice({
            payer: payer,
            merchant: merchant,
            amount: amount,
            expiresAt: expiresAt,
            pqcPubKeyHash: pqcPubKeyHash,
            pqcSigDigest: bytes32(0),
            status: Status.Funded
        });

        emit InvoiceFunded(invoiceId, payer, merchant, amount, pqcPubKeyHash, expiresAt);
    }
}
