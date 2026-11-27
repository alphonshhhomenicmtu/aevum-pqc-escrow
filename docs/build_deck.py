#!/usr/bin/env python3
"""Build the 6-slide 16:9 Aevum PQC Invoice Escrow (QDay) architecture PDF deck."""

from __future__ import annotations

import base64
import re
import subprocess
from pathlib import Path

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
ROOT = Path(__file__).resolve().parent.parent
SCREENSHOTS = ROOT / "docs" / "screenshots"
OUT_PDF = ROOT / "docs" / "aevum-pqc-deck.pdf"
PREVIEW_DIR = Path("/tmp")


def img_data_uri(name: str) -> str:
    raw = (SCREENSHOTS / name).read_bytes()
    return f"data:image/png;base64,{base64.b64encode(raw).decode('ascii')}"


def build_html() -> str:
    s1 = img_data_uri("01-overview.png")
    s2 = img_data_uri("02-lamport-keygen-verify.png")
    s3 = img_data_uri("03-eip3009-escrow-flow.png")
    s4 = img_data_uri("04-quantum-breaker-lab.png")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Aevum PQC Invoice Escrow — Architecture &amp; Security Deck</title>
<style>
  @page {{ size: 13.333in 7.5in; margin: 0; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{
    width: 13.333in;
    background: #070b14;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}
  .slide {{
    width: 13.333in;
    height: 7.5in;
    padding: 0.44in 0.54in 0.40in 0.54in;
    overflow: hidden;
    page-break-after: always;
    break-after: page;
    background:
      radial-gradient(circle at 86% 14%, rgba(168, 85, 247, 0.14), transparent 40%),
      radial-gradient(circle at 14% 86%, rgba(56, 189, 248, 0.11), transparent 42%),
      linear-gradient(160deg, #070b14 0%, #0d1122 55%, #090e1c 100%);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .slide:last-child {{ page-break-after: auto; break-after: auto; }}
  .topbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid rgba(148, 163, 184, 0.18);
    padding-bottom: 10px;
    margin-bottom: 14px;
  }}
  .tag {{
    font-size: 11px; font-weight: 700; letter-spacing: 0.10em; text-transform: uppercase;
    color: #c084fc; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(192, 132, 252, 0.35);
    padding: 4px 10px; border-radius: 999px;
  }}
  .tag-cyan {{ color: #38bdf8; background: rgba(56, 189, 248, 0.12); border-color: rgba(56, 189, 248, 0.35); }}
  .tag-emerald {{ color: #34d399; background: rgba(16, 185, 129, 0.12); border-color: rgba(52, 211, 153, 0.35); }}
  .slide-num {{ font-size: 11px; color: #94a3b8; font-family: monospace; }}
  h1 {{ font-size: 40px; line-height: 1.12; font-weight: 800; letter-spacing: -0.02em; color: #f8fafc; }}
  h2 {{ font-size: 26px; line-height: 1.18; font-weight: 750; color: #f8fafc; margin-bottom: 6px; }}
  .subtitle {{ font-size: 14.5px; line-height: 1.45; color: #94a3b8; }}
  .lead {{ font-size: 17px; line-height: 1.5; color: #cbd5e1; max-width: 9.8in; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; flex: 1; min-height: 0; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; flex: 1; min-height: 0; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }}
  .card {{
    background: rgba(15, 23, 42, 0.80); border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 12px; padding: 15px 17px; display: flex; flex-direction: column;
  }}
  .card-purple {{ border-color: rgba(192, 132, 252, 0.35); background: linear-gradient(180deg, rgba(168, 85, 247, 0.08), rgba(15, 23, 42, 0.85)); }}
  .card-emerald {{ border-color: rgba(52, 211, 153, 0.35); background: linear-gradient(180deg, rgba(16, 185, 129, 0.08), rgba(15, 23, 42, 0.85)); }}
  .card-rose {{ border-color: rgba(251, 113, 133, 0.35); background: linear-gradient(180deg, rgba(251, 113, 133, 0.08), rgba(15, 23, 42, 0.85)); }}
  .card-title {{ font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 8px; }}
  .kpi-val {{ font-size: 27px; font-weight: 800; color: #c084fc; font-family: monospace; line-height: 1.1; margin-bottom: 5px; }}
  .kpi-val.emerald {{ color: #34d399; }}
  .kpi-val.cyan {{ color: #38bdf8; }}
  .kpi-label {{ font-size: 11.5px; color: #94a3b8; line-height: 1.35; }}
  ul.clean {{ list-style: none; display: flex; flex-direction: column; gap: 7px; }}
  ul.clean li {{ font-size: 12.5px; line-height: 1.42; color: #cbd5e1; padding-left: 14px; position: relative; }}
  ul.clean li::before {{ content: ""; position: absolute; left: 0; top: 6px; width: 6px; height: 6px; border-radius: 50%; background: #c084fc; }}
  ul.clean.emerald li::before {{ background: #34d399; }}
  ul.clean.rose li::before {{ background: #fb7185; }}
  code, .mono {{
    font-family: "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
    font-size: 11px; color: #7dd3fc; background: rgba(15, 23, 42, 0.92);
    padding: 1px 5px; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.22);
  }}
  .shot-wrap {{
    background: #050810; border: 1px solid rgba(148, 163, 184, 0.22);
    border-radius: 10px; overflow: hidden; display: flex; flex-direction: column;
  }}
  .shot-wrap img {{ width: 100%; height: 3.55in; object-fit: cover; object-position: top center; display: block; }}
  .shot-cap {{ padding: 7px 11px; font-size: 11px; color: #94a3b8; border-top: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.92); }}
  .footer {{ display: flex; justify-content: space-between; align-items: center; border-top: 1px solid rgba(148, 163, 184, 0.15); padding-top: 8px; margin-top: 10px; font-size: 10.5px; color: #64748b; }}
</style>
</head>
<body>

<!-- SLIDE 1: COVER -->
<section class="slide">
  <div class="topbar">
    <span class="tag">DoraHacks Aevum Builder Challenge #1 (QDay)</span>
    <span class="slide-num">01 / 06</span>
  </div>
  <div style="display:flex; flex-direction:column; gap:18px;">
    <div style="display:flex; gap:10px;">
      <span class="tag tag-cyan">QDay Aevum Testnet (Chain 44005 · Shanghai EVM)</span>
      <span class="tag tag-emerald">Lamport-SHA256 PQC + EIP-3009 Gasless</span>
    </div>
    <h1>Aevum PQC Invoice Escrow</h1>
    <p class="lead">
      Post-Quantum verifiable stablecoin (<code>tUSD8</code>) invoice escrow &amp; gasless EIP-3009 settlement prototype
      targeting <strong style="color:#f8fafc;">QDay Aevum Testnet (Chain ID 44005)</strong>.
    </p>
    <div class="grid-4">
      <div class="card card-emerald">
        <div class="kpi-val emerald">8 / 8</div>
        <div class="kpi-label">Foundry tests PASS (<code>evm_version = "shanghai"</code>, <code>solc 0.8.28</code>)</div>
      </div>
      <div class="card card-purple">
        <div class="kpi-val">6 / 6</div>
        <div class="kpi-label">Python PQC Verifier <code>pytest -v</code> PASS (<code>tests/test_pqc_verifier.py</code>)</div>
      </div>
      <div class="card">
        <div class="kpi-val emerald">0 H / 0 M</div>
        <div class="kpi-label">Slither static analysis findings on <code>PqcInvoiceEscrow.sol</code></div>
      </div>
      <div class="card">
        <div class="kpi-val cyan">1.10M gas</div>
        <div class="kpi-label">Dry-run deploy verified on live RPC <code>0xabe5</code> (Chain 44005)</div>
      </div>
    </div>
    <div class="card" style="padding:12px 16px; display:grid; grid-template-columns: 1fr 1fr 1fr; gap:14px;">
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">Live Web Console</div>
        <div class="mono" style="margin-top:4px;">https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/</div>
      </div>
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">GitHub Repository (Apache-2.0)</div>
        <div class="mono" style="margin-top:4px;">https://github.com/alphonshhhomenicmtu/aevum-pqc-escrow</div>
      </div>
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">Demo Video (YouTube)</div>
        <div class="mono" style="margin-top:4px;">https://www.youtube.com/watch?v=nkpk0sRM6qs</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span>Aevum PQC Invoice Escrow · Hash-Based Post-Quantum Settlement on QDay</span>
    <span>Apache-2.0 · Zero Console Errors</span>
  </div>
</section>

<!-- SLIDE 2: POST-QUANTUM ESCROW PROBLEM -->
<section class="slide">
  <div class="topbar">
    <span class="tag">02 · The Post-Quantum Escrow Problem</span>
    <span class="slide-num">02 / 06</span>
  </div>
  <div>
    <h2>Why Long-Lived Stablecoin Escrows Need Post-Quantum Authorization</h2>
    <p class="subtitle">Standard ECDSA signatures on secp256k1 face existential quantum risk, while B2B invoices still require gasless UX on Shanghai EVM.</p>
  </div>
  <div class="grid-2" style="margin-top:14px;">
    <div class="card card-rose">
      <div class="card-title" style="color:#fda4af;">Classical ECDSA-Only Escrow Vulnerabilities</div>
      <ul class="clean rose">
        <li><strong>Shor's Algorithm Exposure:</strong> Any exposed ECDSA public key allows a future fault-tolerant quantum computer to derive the private key and drain escrowed funds.</li>
        <li><strong>No Hash-Based Release Gate:</strong> Standard escrows rely solely on <code>ecrecover</code>, offering zero quantum-resistant proof for high-value invoice releases.</li>
        <li><strong>EVM Compatibility Gaps:</strong> Many PQC schemes require custom precompiles unavailable on Shanghai-era EVM chains like QDay 44005.</li>
      </ul>
    </div>
    <div class="card card-emerald">
      <div class="card-title" style="color:#6ee7b7;">Aevum PQC Escrow Design</div>
      <ul class="clean emerald">
        <li><strong>On-Chain 256-Bit Lamport-SHA256:</strong> Relies purely on collision-resistant SHA-256 preimage proofs (quantum-safe under Grover's bound) on Shanghai EVM.</li>
        <li><strong>Gasless EIP-3009 Funding:</strong> Supports both standard <code>fund()</code> and gasless <code>fundWithAuthorization()</code> on <code>tUSD8</code>.</li>
        <li><strong>One-Time Key Binding &amp; Expiry:</strong> Enforces single-use Lamport public-key commitments and deterministic <code>refundExpired()</code> recovery.</li>
      </ul>
    </div>
  </div>
  <div class="footer">
    <span>Target Stablecoin: tUSD8 (0x456569838f1d43009A91ebA4263147Afd7233483) on QDay 44005</span>
    <span>Shanghai EVM Native</span>
  </div>
</section>

<!-- SLIDE 3: LAMPORT-SHA256 & EIP-3009 ARCHITECTURE -->
<section class="slide">
  <div class="topbar">
    <span class="tag tag-cyan">03 · Lamport-SHA256 &amp; EIP-3009 Architecture</span>
    <span class="slide-num">03 / 06</span>
  </div>
  <div>
    <h2>WebCrypto / Python PQC Signer &rarr; <code>PqcInvoiceEscrow.sol</code></h2>
    <p class="subtitle">Zero-dependency Python &amp; browser WebCrypto Lamport-SHA256 keygen/sign/verify paired with EIP-3009 gasless stablecoin funding.</p>
  </div>
  <div class="grid-2" style="margin-top:10px;">
    <div class="shot-wrap">
      <img src="{s2}" alt="Lamport Keygen and Verify" />
      <div class="shot-cap"><strong>Lamport-SHA256 Keygen &amp; Verify:</strong> Generates 256-bit one-time keypairs, canonical invoice commitments, and preimage proofs in-browser.</div>
    </div>
    <div class="shot-wrap">
      <img src="{s3}" alt="EIP-3009 Escrow Flow" />
      <div class="shot-cap"><strong>EIP-3009 Gasless Escrow Flow:</strong> <code>fundWithAuthorization</code> deposits <code>tUSD8</code>; <code>releaseWithLamportProof</code> settles on-chain.</div>
    </div>
  </div>
  <div class="footer">
    <span>Contracts: PqcInvoiceEscrow.sol · Verifier: pqc_verifier/ · Console: web/</span>
    <span>Full End-to-End Flow</span>
  </div>
</section>

<!-- SLIDE 4: 4-SCENARIO QUANTUM BREAKER LAB -->
<section class="slide">
  <div class="topbar">
    <span class="tag">04 · 4-Scenario Quantum Breaker Lab</span>
    <span class="slide-num">04 / 06</span>
  </div>
  <div>
    <h2>Interactive Adversarial Testing in the Browser Console</h2>
    <p class="subtitle">Judges can trigger four deterministic attack scenarios against <code>PqcInvoiceEscrow.sol</code> logic and verify immediate rejection.</p>
  </div>
  <div class="grid-2" style="margin-top:10px; align-items:stretch;">
    <div class="shot-wrap">
      <img src="{s4}" alt="Quantum Breaker Lab" style="height:4.25in;" />
      <div class="shot-cap"><strong>Adversarial Quantum Breaker Lab:</strong> Live browser verification of forged preimages, key reuse, and expiry races.</div>
    </div>
    <div class="card card-purple" style="justify-content:center;">
      <div class="card-title" style="color:#e9d5ff;">Four Tested Adversarial Attack Vectors</div>
      <ul class="clean">
        <li><strong>1. Forged Lamport Preimage:</strong> Corrupting even a single bit-branch in the 256-element SHA-256 signature fails on-chain commitment verification.</li>
        <li><strong>2. One-Time Signature Replay:</strong> Attempting to reuse a consumed Lamport public key or already-settled invoice ID reverts immediately.</li>
        <li><strong>3. Expired Invoice Release Race:</strong> Calling <code>releaseWithLamportProof</code> after expiry or double-claiming after <code>refundExpired</code> is blocked.</li>
        <li><strong>4. Invalid EIP-3009 Authorization:</strong> Tampered payer, nonce, or deadline in <code>fundWithAuthorization</code> is rejected before state mutation.</li>
      </ul>
    </div>
  </div>
  <div class="footer">
    <span>Interactive Lab live at https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/</span>
    <span>4/4 Attack Scenarios Blocked</span>
  </div>
</section>

<!-- SLIDE 5: FORGE 13/13 SHANGHAI + PYTEST 26/26 + SLITHER 0 H/M + CHAIN 44005 PROOF -->
<section class="slide">
  <div class="topbar">
    <span class="tag tag-emerald">05 · Verification &amp; Chain 44005 Proof</span>
    <span class="slide-num">05 / 06</span>
  </div>
  <div>
    <h2>Foundry 13/13 (Shanghai) + Pytest 26/26 + Slither 0 H/M + QDay Dry-Run</h2>
    <p class="subtitle">Verified offline with Foundry (`solc 0.8.28`, `evm_version = "shanghai"`), Python pytest, Slither, and live QDay Chain `44005` RPC.</p>
  </div>
  <div class="grid-2" style="margin-top:10px; align-items:stretch;">
    <div class="shot-wrap">
      <img src="{s1}" alt="Aevum PQC Overview" style="height:4.25in;" />
      <div class="shot-cap"><strong>Live Web Console Overview:</strong> 4&times; 1920&times;1080 headless Chrome screenshots verified with 0 console errors &amp; 0 page errors.</div>
    </div>
    <div style="display:flex; flex-direction:column; gap:12px;">
      <div class="card card-emerald">
        <div class="card-title" style="color:#6ee7b7;">Test &amp; Static Analysis Proof</div>
        <ul class="clean emerald">
          <li><strong>Foundry (<code>forge test --offline -vv</code>):</strong> <code>13/13</code> tests passing (12 unit tests in <code>PqcInvoiceEscrow.t.sol</code> plus 1 invariant suite, Shanghai EVM).</li>
          <li><strong>Python PQC Verifier (<code>pytest -v</code>):</strong> <code>26/26</code> tests passing in <code>tests/test_pqc_verifier.py</code>.</li>
          <li><strong>Slither Static Analysis:</strong> <code>0</code> High / <code>0</code> Medium issues on <code>PqcInvoiceEscrow.sol</code>.</li>
        </ul>
      </div>
      <div class="card card-purple">
        <div class="card-title" style="color:#e9d5ff;">Live QDay Chain <code>44005</code> RPC &amp; Deploy Dry-Run</div>
        <ul class="clean">
          <li><strong>RPC Endpoint:</strong> <code>https://rpc-test.qday.info</code> live (<code>eth_chainId = 0xabe5</code>, <code>eth_blockNumber = 0x3ff6e0</code>).</li>
          <li><strong>Turnkey Script:</strong> <code>scripts/deploy_aevum.sh --dry-run</code> simulation passed (<code>PqcInvoiceEscrow</code>, <code>1,102,379</code> gas).</li>
          <li><strong>Stablecoin Target:</strong> <code>tUSD8</code> at <code>0x456569838f1d43009A91ebA4263147Afd7233483</code>.</li>
        </ul>
      </div>
    </div>
  </div>
  <div class="footer">
    <span>Verified Demo Video: 97.81s, 1920x1080, 30fps, -14 LUFS, YouTube oEmbed HTTP 200</span>
    <span>Chain 44005 Ready</span>
  </div>
</section>

<!-- SLIDE 6: ROADMAP -->
<section class="slide">
  <div class="topbar">
    <span class="tag tag-cyan">06 · Roadmap &amp; Open-Source Deliverables</span>
    <span class="slide-num">06 / 06</span>
  </div>
  <div>
    <h2>Production Post-Quantum Settlement Roadmap on QDay</h2>
    <p class="subtitle">Apache-2.0 open-source foundation ready for live QDay testnet broadcast and multi-invoice PQC key trees.</p>
  </div>
  <div class="grid-3" style="margin-top:14px;">
    <div class="card card-emerald">
      <div class="card-title" style="color:#6ee7b7;">Phase 1 · Live Chain 44005 Deploy</div>
      <ul class="clean emerald">
        <li>Broadcast <code>PqcInvoiceEscrow.sol</code> via <code>scripts/deploy_aevum.sh</code>.</li>
        <li>Bind live <code>tUSD8</code> EIP-3009 relayer for zero-gas payer onboarding.</li>
      </ul>
    </div>
    <div class="card card-purple">
      <div class="card-title" style="color:#e9d5ff;">Phase 2 · Merkle / XMSS Key Trees</div>
      <ul class="clean">
        <li>Upgrade from single-use Lamport keys to Merkle-authenticated XMSS trees for reusable merchant signing.</li>
        <li>Batch invoice settlement proofs to amortize calldata gas.</li>
      </ul>
    </div>
    <div class="card">
      <div class="card-title" style="color:#7dd3fc;">Phase 3 · Merchant PQC SDK</div>
      <ul class="clean">
        <li>Publish npm &amp; PyPI packages wrapping WebCrypto + <code>pqc_verifier/</code>.</li>
        <li>Drop-in checkout widget for QDay ecosystem dApps.</li>
      </ul>
    </div>
  </div>
  <div class="card" style="margin-top:14px; padding:12px 16px; flex:0 0 auto;">
    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:14px;">
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">Live Web Console</div>
        <div class="mono" style="margin-top:4px;">https://alphonshhhomenicmtu.github.io/aevum-pqc-escrow/</div>
      </div>
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">GitHub Repository (Apache-2.0)</div>
        <div class="mono" style="margin-top:4px;">https://github.com/alphonshhhomenicmtu/aevum-pqc-escrow</div>
      </div>
      <div>
        <div style="font-size:10.5px; color:#94a3b8; text-transform:uppercase; font-weight:700;">Demo Video</div>
        <div class="mono" style="margin-top:4px;">https://www.youtube.com/watch?v=nkpk0sRM6qs</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span>DoraHacks Aevum Builder Challenge #1 (QDay) · Chain ID 44005</span>
    <span>Apache-2.0 · Zero Secrets</span>
  </div>
</section>

</body>
</html>
"""


def main() -> None:
    OUT_PDF.parent.mkdir(parents=True, exist_ok=True)
    html = build_html()
    html_path = PREVIEW_DIR / "aevum_pqc_deck.html"
    html_path.write_text(html, encoding="utf-8")

    subprocess.run(
        [
            CHROME,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--user-data-dir=/tmp/chrome_aevum_pdf",
            "--no-pdf-header-footer",
            f"--print-to-pdf={OUT_PDF}",
            html_path.as_uri(),
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not OUT_PDF.exists() or OUT_PDF.stat().st_size < 10000:
        raise RuntimeError(f"Failed to generate {OUT_PDF}")

    head_end = html.index("<body>") + len("<body>")
    head = html[:head_end]
    slides = re.findall(r"(<section class=\"slide\">.*?</section>)", html, flags=re.S)
    for idx, name in [(0, "aevum_slide1.png"), (3, "aevum_slide4.png")]:
        single_html = PREVIEW_DIR / f"_tmp_ae_{idx}.html"
        single_html.write_text(head + slides[idx] + "</body></html>", encoding="utf-8")
        out_png = PREVIEW_DIR / name
        subprocess.run(
            [
                CHROME,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                f"--user-data-dir=/tmp/chrome_aevum_png_{idx}",
                "--window-size=1280,720",
                f"--screenshot={out_png}",
                single_html.as_uri(),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not out_png.exists() or out_png.stat().st_size < 1000:
            raise RuntimeError(f"Failed to generate {out_png}")

    print(f"PDF_BUILT: {OUT_PDF} ({OUT_PDF.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
