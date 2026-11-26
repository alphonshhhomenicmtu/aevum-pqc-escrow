# DoraHacks Aevum Builder Challenge #1 (QDay) — Submission Ready

## Portal Fields
- **Hackathon**: Aevum Builder Challenge #1 (QDay) — `https://dorahacks.io/hackathon/qday/detail`
- **Project Name**: **Aevum PQC Invoice Escrow**
- **Tagline**: Post-Quantum verifiable `tUSD8` invoice escrow with gasless EIP-3009 settlement on QDay Aevum Testnet (Chain 44005, Shanghai EVM).
- **GitHub Repository**: `https://github.com/alphonshhhomenicmtu/aevum-pqc-escrow`
- **Live Demo (GitHub Pages)**: `https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/`
- **Demo Video (YouTube, Public)**: `https://www.youtube.com/watch?v=nkpk0sRM6qs`
- **Demo Video (Google Drive Mirror)**: `https://drive.google.com/file/d/1t5ARAbQjU2kRelXB5-MEDg-ze2rieTbt/view?usp=sharing`
- **License**: Apache-2.0

## Verification Summary
- **Foundry (`forge test --offline -vv`, Shanghai EVM, `solc 0.8.28`)**: **8/8 passed** (`PqcInvoiceEscrow.t.sol`)
- **Python PQC Verifier (`pytest -v`)**: **6/6 passed** (`tests/test_pqc_verifier.py`)
- **Slither Static Analysis**: **0 High / 0 Medium** issues on `PqcInvoiceEscrow.sol`
- **QDay Chain `44005` RPC & Dry-Run Deploy**:
  - RPC `https://rpc-test.qday.info` live (`eth_chainId = 0xabe5`, `eth_blockNumber = 0x3ff6e0`)
  - `scripts/deploy_aevum.sh --dry-run` simulation passed (`PqcInvoiceEscrow`, `1,102,379` gas)
- **Live Web Console (`web/`)**: 4x 1920x1080 headless Chrome screenshots captured (`0` console errors, `0` page errors)
- **1080p Demo Video**: `97.81s`, `1920x1080`, `30fps`, `-14 LUFS` normalized English voiceover, YouTube oEmbed `HTTP 200`
