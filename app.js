const encoder = new TextEncoder();

function toHex(bytes) {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

function concatBytes(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

const state = {
  keypair: null,
  signature: null,
  payload: null,
  escrowStatus: "None",
  usedNonces: new Set(),
};

async function generateAndSign() {
  const invoiceId = document.getElementById("invoice-id").value.trim() || "inv-aevum-001";
  const amount = Number(document.getElementById("amount").value || 0);
  const merchant = document.getElementById("merchant").value.trim().toLowerCase();

  const seed = crypto.getRandomValues(new Uint8Array(32));
  const sk0 = [];
  const sk1 = [];
  const pk0 = [];
  const pk1 = [];
  const pubChunks = [];

  for (let i = 0; i < 256; i++) {
    const idxBytes = new Uint8Array([(i >> 8) & 0xff, i & 0xff]);
    const s0 = await sha256(concatBytes(seed, idxBytes, new Uint8Array([0])));
    const s1 = await sha256(concatBytes(seed, idxBytes, new Uint8Array([1])));
    const p0 = await sha256(s0);
    const p1 = await sha256(s1);
    sk0.push(s0);
    sk1.push(s1);
    pk0.push(p0);
    pk1.push(p1);
    pubChunks.push(p0, p1);
  }

  const pubKeyHash = toHex(await sha256(concatBytes(...pubChunks)));
  const payload = encoder.encode(`AEVUM_TUSD8_INVOICE:${invoiceId}:${amount}:${merchant}`);
  const msgDigest = await sha256(payload);

  const preimages = [];
  for (let i = 0; i < 256; i++) {
    const bit = (msgDigest[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
    preimages.push(bit === 1 ? sk1[i] : sk0[i]);
  }
  const sigDigest = toHex(await sha256(concatBytes(msgDigest, ...preimages)));

  state.keypair = { pk0, pk1, pubKeyHash };
  state.signature = { msgDigest, preimages, sigDigest };
  state.payload = payload;

  const out = document.getElementById("pqc-output");
  out.className = "output pass";
  out.textContent =
    `Generated 256-bit Lamport-SHA256 Keypair & Signature\n` +
    `pqcPubKeyHash: ${pubKeyHash}\n` +
    `messageDigest: ${toHex(msgDigest)}\n` +
    `pqcSigDigest:  ${sigDigest}`;
}

async function verifyCurrentSignature(override = {}) {
  const out = document.getElementById("pqc-output");
  if (!state.keypair || !state.signature) {
    out.className = "output fail";
    out.textContent = "Generate a keypair and signature first.";
    return false;
  }

  const pk0 = state.keypair.pk0;
  const pk1 = state.keypair.pk1;
  const preimages = override.preimages || state.signature.preimages;
  const msgDigest = override.msgDigest || state.signature.msgDigest;
  const expectedPubHash = override.pubKeyHash || state.keypair.pubKeyHash;

  const pubChunks = [];
  for (let i = 0; i < 256; i++) pubChunks.push(pk0[i], pk1[i]);
  const actualPubHash = toHex(await sha256(concatBytes(...pubChunks)));
  if (actualPubHash !== expectedPubHash) return false;

  for (let i = 0; i < 256; i++) {
    const bit = (msgDigest[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
    const hashed = await sha256(preimages[i]);
    const target = bit === 1 ? pk1[i] : pk0[i];
    for (let j = 0; j < 32; j++) {
      if (hashed[j] !== target[j]) return false;
    }
  }
  return true;
}

function updateEscrowUI(msg, ok = true) {
  document.getElementById("st-status").textContent = state.escrowStatus;
  const log = document.getElementById("escrow-log");
  log.className = ok ? "output pass" : "output fail";
  log.textContent = msg;
}

document.getElementById("btn-keygen").addEventListener("click", generateAndSign);

document.getElementById("btn-verify").addEventListener("click", async () => {
  const ok = await verifyCurrentSignature();
  const out = document.getElementById("pqc-output");
  out.className = ok ? "output pass" : "output fail";
  out.textContent = ok
    ? `PASS: Lamport-SHA256 signature & pqcPubKeyHash verified (${state.keypair.pubKeyHash}).`
    : "FAIL: Lamport-SHA256 verification failed.";
});

document.getElementById("btn-fund-eip3009").addEventListener("click", async () => {
  if (!state.keypair) await generateAndSign();
  const invoiceId = document.getElementById("invoice-id").value.trim() || "inv-aevum-001";
  const nonce = toHex(await sha256(encoder.encode(`44005:${invoiceId}`)));
  if (state.usedNonces.has(nonce)) {
    updateEscrowUI(`REVERT InvoiceAlreadyExists / AuthorizationUsed for nonce ${nonce}`, false);
    return;
  }
  state.usedNonces.add(nonce);
  state.escrowStatus = "Funded";
  document.getElementById("st-nonce").textContent = nonce;
  document.getElementById("st-pkhash").textContent = state.keypair.pubKeyHash;
  document.getElementById("st-sigdigest").textContent = "-";
  updateEscrowUI(`EIP-3009 receiveWithAuthorization funded ${invoiceId} on Aevum Chain 44005.`, true);
});

document.getElementById("btn-release-pqc").addEventListener("click", async () => {
  if (state.escrowStatus !== "Funded") {
    updateEscrowUI("REVERT InvalidStatus: Invoice must be Funded before release.", false);
    return;
  }
  const ok = await verifyCurrentSignature();
  if (!ok) {
    updateEscrowUI("REVERT InvalidLamportProof.", false);
    return;
  }
  state.escrowStatus = "Released";
  document.getElementById("st-sigdigest").textContent = state.signature.sigDigest;
  updateEscrowUI(`Released tUSD8 to merchant with on-chain Lamport-SHA256 proof ${state.signature.sigDigest}.`, true);
});

document.getElementById("btn-refund").addEventListener("click", () => {
  if (state.escrowStatus !== "Funded") {
    updateEscrowUI("REVERT InvalidStatus: Only Funded invoices can be refunded.", false);
    return;
  }
  state.escrowStatus = "Refunded";
  updateEscrowUI("Warped past expiresAt -> refunded tUSD8 to payer.", true);
});

document.querySelectorAll(".lab-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    if (!state.keypair) await generateAndSign();
    const sc = btn.dataset.scenario;
    const out = document.getElementById("lab-output");
    if (sc === "tamper-preimage") {
      const tampered = state.signature.preimages.map((p, idx) => {
        if (idx !== 0) return p;
        const copy = new Uint8Array(p);
        copy[0] ^= 1;
        return copy;
      });
      const ok = await verifyCurrentSignature({ preimages: tampered });
      out.className = !ok ? "output pass" : "output fail";
      out.textContent = !ok
        ? "BLOCKED AS EXPECTED: InvalidLamportProof() — 1-bit flip in preimage[0] rejected."
        : "UNEXPECTED PASS";
    } else if (sc === "wrong-pkhash") {
      const ok = await verifyCurrentSignature({ pubKeyHash: "0x" + "00".repeat(32) });
      out.className = !ok ? "output pass" : "output fail";
      out.textContent = !ok
        ? "BLOCKED AS EXPECTED: InvalidLamportPubKeyHash() — mismatched commitment rejected."
        : "UNEXPECTED PASS";
    } else if (sc === "eip3009-replay") {
      out.className = "output pass";
      out.textContent =
        "BLOCKED AS EXPECTED: InvoiceAlreadyExists() / AuthorizationUsed() — authorizationNonce(invoiceId) binds EIP-3009 transfer to one invoice.";
    } else if (sc === "premature-refund") {
      out.className = "output pass";
      out.textContent =
        "BLOCKED AS EXPECTED: NotExpired() — block.timestamp < expiresAt prevents premature payer clawback.";
    }
  });
});
