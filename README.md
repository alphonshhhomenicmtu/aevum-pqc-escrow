# Aevum PQC Invoice Escrow

Post-Quantum verifiable stablecoin (`tUSD8`) escrow & EIP-3009 gasless settlement prototype targeting **QDay Aevum Testnet** (Chain ID `44005`, Shanghai EVM).

- **Live Web Console**: https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/
- **Architecture & Security Deck (PDF)**: https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/aevum-pqc-deck.pdf ([`docs/aevum-pqc-deck.pdf`](docs/aevum-pqc-deck.pdf))
- **Demo Video (YouTube)**: https://www.youtube.com/watch?v=nkpk0sRM6qs
- **Demo Video (Google Drive)**: https://drive.google.com/file/d/1t5ARAbQjU2kRelXB5-MEDg-ze2rieTbt/view?usp=sharing

## Architecture
- `contracts/src/PqcInvoiceEscrow.sol`: Shanghai-compatible `tUSD8` (`0x456569838f1d43009A91ebA4263147Afd7233483`) escrow supporting standard `fund`, gasless EIP-3009 `fundWithAuthorization`, on-chain 256-bit Lamport-SHA256 proof verification (`releaseWithLamportProof`), and `refundExpired`. The EIP-3009 nonce is `keccak256(abi.encode(chainid, escrow, invoiceId, payer, merchant, amount, expiresAt, pqcPubKeyHash))`. Lamport release accepts only `sha256(abi.encode(invoiceId, amount, payer, merchant, chainid, escrow))`.
- `pqc_verifier/`: Zero-dependency Python hash-based Post-Quantum One-Time Signature (Lamport-SHA256) keygen, signing, verification, and canonical invoice commitment builder.
- `web/`: Local simulator. In-browser WebCrypto Lamport-SHA256 keygen is real. EIP-3009 fund, release, and refund buttons only simulate the state machine and do not broadcast `PqcInvoiceEscrow`. Includes the 4-scenario adversarial lab.
- `scripts/deploy_aevum.sh`: Turnkey QDay Chain `44005` Foundry deploy script (`PRIVATE_KEY` & `RPC_URL` via env vars, `--dry-run` verified).

## Verification
- **Foundry (`evm_version = "shanghai"`)**: `15/15` tests passing (`forge test --offline`: 14 unit tests + 1 stateful handler invariant suite with 256 runs / 8,192 calls, 0 reverts, proving escrow accounting conservation, no double-settlement, timelock enforcement, tampered Lamport proof rejection, and relayer substitution of merchant / expiresAt / pqcPubKeyHash reverting `InvalidSigner`)
- **Python PQC Verifier**: `31/31` adversarial tests passing (`pytest -q`)
- **Slither**: `0` High / `0` Medium findings (`--fail-medium` exit 0)
- **Gitleaks**: `0` secrets detected

## Screenshots
- [Overview](docs/screenshots/01-overview.png)
- [Lamport-SHA256 Keygen & Verify](docs/screenshots/02-lamport-keygen-verify.png)
- [EIP-3009 Gasless Escrow Flow](docs/screenshots/03-eip3009-escrow-flow.png)
- [Adversarial Quantum Breaker Lab](docs/screenshots/04-quantum-breaker-lab.png)
