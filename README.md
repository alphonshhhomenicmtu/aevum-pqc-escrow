# Aevum PQC Invoice Escrow — Phase 1 Prototype

Post-Quantum verifiable stablecoin (`tUSD8`) escrow & EIP-3009 gasless settlement prototype targeting **QDay Aevum Testnet** (Chain ID `44005`, Shanghai EVM).

## Components
- `contracts/src/PqcInvoiceEscrow.sol`: Shanghai-compatible `tUSD8` escrow supporting standard `pay`, gasless EIP-3009 `payWithAuthorization`, post-quantum `pqcPubKeyHash` / `pqcSigDigest` attestation, and expiry refunds.
- `pqc_verifier/`: Zero-dependency Python hash-based Post-Quantum One-Time Signature (Lamport-SHA256) keygen, signing, verification, and on-chain commitment builder.
