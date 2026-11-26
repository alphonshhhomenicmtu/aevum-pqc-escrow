# Aevum PQC Invoice Escrow

Post-Quantum verifiable stablecoin (`tUSD8`) escrow & EIP-3009 gasless settlement prototype targeting **QDay Aevum Testnet** (Chain ID `44005`, Shanghai EVM).

- **Live Web Console**: https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/
- **Demo Video (YouTube)**: https://www.youtube.com/watch?v=nkpk0sRM6qs
- **Demo Video (Google Drive)**: https://drive.google.com/file/d/1t5ARAbQjU2kRelXB5-MEDg-ze2rieTbt/view?usp=sharing

## Architecture
- `contracts/src/PqcInvoiceEscrow.sol`: Shanghai-compatible `tUSD8` (`0x456569838f1d43009A91ebA4263147Afd7233483`) escrow supporting standard `fund`, gasless EIP-3009 `fundWithAuthorization`, on-chain 256-bit Lamport-SHA256 proof verification (`releaseWithLamportProof`), and `refundExpired`.
- `pqc_verifier/`: Zero-dependency Python hash-based Post-Quantum One-Time Signature (Lamport-SHA256) keygen, signing, verification, and canonical invoice commitment builder.
- `web/`: Interactive WebCrypto Lamport-SHA256 keygen/sign/verify console, EIP-3009 escrow simulator, and 4-Scenario Adversarial Quantum Breaker Lab.
- `scripts/deploy_aevum.sh`: Turnkey QDay Chain `44005` Foundry deploy script (`PRIVATE_KEY` & `RPC_URL` via env vars, `--dry-run` verified).

## Verification
- **Foundry (`evm_version = "shanghai"`)**: `8/8` tests passing (`forge test --offline -vv`)
- **Python PQC Verifier**: `6/6` tests passing (`pytest -v`)
- **Slither**: `0` High / `0` Medium findings

## Screenshots
- [Overview](docs/screenshots/01-overview.png)
- [Lamport-SHA256 Keygen & Verify](docs/screenshots/02-lamport-keygen-verify.png)
- [EIP-3009 Gasless Escrow Flow](docs/screenshots/03-eip3009-escrow-flow.png)
- [Adversarial Quantum Breaker Lab](docs/screenshots/04-quantum-breaker-lab.png)
