# Aevum PQC Invoice Escrow — 1080p Demo Narration Script (~80s)

1. **Scene 1 — Overview & Problem (0:00–0:16)**:
   "Welcome to Aevum PQC Invoice Escrow, built for QDay Aevum Testnet, Chain ID 44005, on the Shanghai EVM. Standard stablecoin checkouts rely solely on ECDSA signatures. We pair gasless tUSD8 EIP-3009 settlement with on-chain Post-Quantum Lamport-SHA256 verification."

2. **Scene 2 — Local Simulator Lamport-SHA256 Keygen (0:16–0:32)**:
   "First, in the local web simulator, the browser generates a 256-bit Lamport-SHA256 one-time keypair using WebCrypto, hashes the public key into pqcPubKeyHash, and signs the canonical tUSD8 invoice commitment to produce pqcSigDigest. The escrow buttons simulate settlement. They do not broadcast PqcInvoiceEscrow."

3. **Scene 3 — EIP-3009 Gasless Escrow Flow (0:32–0:48)**:
   "Next, a buyer funds the invoice gaslessly via tUSD8 receiveWithAuthorization, bound to an order-specific authorizationNonce. When delivery completes, the merchant calls releaseWithLamportProof, which verifies all 256 SHA-256 preimages directly on-chain before releasing tUSD8."

4. **Scene 4 — Adversarial Quantum Breaker Lab (0:48–1:04)**:
   "In the Adversarial Quantum Breaker Lab, we test four failure modes: flipping a single bit in a Lamport preimage, supplying a mismatched public key hash, replaying an EIP-3009 nonce, and attempting a premature refund. Every attack is deterministically blocked."

5. **Scene 5 — Verification & Deployment Readiness (1:04–1:20)**:
   "The entire stack is verified offline and on QDay RPC: thirteen of thirteen Foundry Shanghai tests pass, twenty-six of twenty-six Python PQC tests pass, Slither reports zero high or medium findings, and our turnkey Chain 44005 deploy dry-run succeeds cleanly. The web console remains a local simulator."
