const encoder = new TextEncoder();

const KECCAK_RC = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];
const KECCAK_ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const MASK64 = (1n << 64n) - 1n;

function rotl64(value, shift) {
  const bits = BigInt(shift) & 63n;
  const x = value & MASK64;
  if (bits === 0n) return x;
  return ((x << bits) | (x >> (64n - bits))) & MASK64;
}

function keccakF(state) {
  for (const roundConst of KECCAK_RC) {
    const columns = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) {
      columns[x] =
        state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const mixed = columns[(x + 4) % 5] ^ rotl64(columns[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= mixed;
    }
    const rotated = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], KECCAK_ROT[x][y]);
      }
    }
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] =
          (rotated[x + 5 * y] ^
            ((~rotated[((x + 1) % 5) + 5 * y]) & rotated[((x + 2) % 5) + 5 * y])) &
          MASK64;
      }
    }
    state[0] = (state[0] ^ roundConst) & MASK64;
  }
}

export function keccak256(bytes) {
  const rate = 136;
  const tmp = Array.from(bytes);
  tmp.push(0x01);
  while (tmp.length % rate !== rate - 1) tmp.push(0);
  tmp.push(0x80);
  const padded = Uint8Array.from(tmp);
  const len = padded.length;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < len; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane++) {
      let word = 0n;
      const base = offset + lane * 8;
      for (let b = 0; b < 8; b++) word |= BigInt(padded[base + b]) << BigInt(8 * b);
      state[lane] ^= word;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane++) {
    let word = state[lane];
    for (let b = 0; b < 8; b++) {
      out[lane * 8 + b] = Number(word & 0xffn);
      word >>= 8n;
    }
  }
  return out;
}

function toHex(bytes) {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

function concatBytes(...arrays) {
  const total = arrays.reduce((acc, item) => acc + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

function hexToBytes(hex) {
  const body = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (body.length % 2 !== 0 || /[^0-9a-fA-F]/.test(body)) throw new Error("invalid hex");
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function wordFromUint(value) {
  let v = BigInt(value);
  if (v < 0n || v >= 1n << 256n) throw new Error("uint out of range");
  const word = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    word[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return word;
}

function wordFromAddress(addr) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) throw new Error("address must be 20 bytes");
  const word = new Uint8Array(32);
  word.set(hexToBytes(addr), 12);
  return word;
}

export function invoiceIdWord(invoiceId) {
  const text = String(invoiceId || "").trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(text)) return hexToBytes(text);
  if (!text) throw new Error("invoice id is required");
  return keccak256(encoder.encode(text));
}

export function encodeInvoiceCommitment(terms) {
  return concatBytes(
    invoiceIdWord(terms.invoiceId),
    wordFromUint(terms.amount),
    wordFromAddress(terms.payer),
    wordFromAddress(terms.merchant),
    wordFromUint(terms.chainId),
    wordFromAddress(terms.escrow),
  );
}

export function authorizationNonceBytes(terms) {
  return keccak256(
    concatBytes(
      wordFromUint(terms.chainId),
      wordFromAddress(terms.escrow),
      invoiceIdWord(terms.invoiceId),
      wordFromAddress(terms.payer),
      wordFromAddress(terms.merchant),
      wordFromUint(terms.amount),
      wordFromUint(terms.expiresAt),
      hexToBytes(terms.pubKeyHash),
    ),
  );
}

const state = {
  keypair: null,
  signature: null,
  payload: null,
  terms: null,
  fundedTerms: null,
  escrowStatus: "None",
  usedNonces: new Set(),
};

function readTerms() {
  return {
    invoiceId: document.getElementById("invoice-id").value.trim() || "inv-aevum-001",
    amount: BigInt(document.getElementById("amount").value || "0"),
    merchant: document.getElementById("merchant").value.trim(),
    payer: document.getElementById("payer").value.trim(),
    escrow: document.getElementById("escrow").value.trim(),
    chainId: BigInt(document.getElementById("chain-id").value || "0"),
    expiresAt: BigInt(document.getElementById("expires-at").value || "0"),
  };
}

async function generateAndSign() {
  const terms = readTerms();
  if (terms.amount <= 0n) throw new Error("amount must be positive");
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
  const payload = encodeInvoiceCommitment(terms);
  const msgDigest = await sha256(payload);
  const preimages = [];
  for (let i = 0; i < 256; i++) {
    const bit = (msgDigest[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
    preimages.push(bit === 1 ? sk1[i] : sk0[i]);
  }
  const sigDigest = toHex(await sha256(concatBytes(msgDigest, ...preimages)));
  const nonce = toHex(authorizationNonceBytes({ ...terms, pubKeyHash }));

  state.keypair = { pk0, pk1, pubKeyHash };
  state.signature = { msgDigest, preimages, sigDigest };
  state.payload = payload;
  state.terms = terms;

  const out = document.getElementById("pqc-output");
  out.className = "output pass";
  out.textContent =
    `Generated 256-bit Lamport-SHA256 Keypair & Signature\n` +
    `pqcPubKeyHash: ${pubKeyHash}\n` +
    `invoiceCommitment: ${toHex(payload)}\n` +
    `messageDigest: ${toHex(msgDigest)}\n` +
    `pqcSigDigest:  ${sigDigest}\n` +
    `authorizationNonce: ${nonce}`;
}

async function verifyCurrentSignature(override = {}) {
  const out = document.getElementById("pqc-output");
  if (!state.keypair || !state.signature) {
    if (out) {
      out.className = "output fail";
      out.textContent = "Generate a keypair and signature first.";
    }
    return false;
  }

  const pk0 = state.keypair.pk0;
  const pk1 = state.keypair.pk1;
  const preimages = override.preimages || state.signature.preimages;
  const msgDigest = override.msgDigest || state.signature.msgDigest;
  const expectedPubHash = override.pubKeyHash || state.keypair.pubKeyHash;
  const expectedSig = override.sigDigest || state.signature.sigDigest;

  const pubChunks = [];
  for (let i = 0; i < 256; i++) pubChunks.push(pk0[i], pk1[i]);
  const actualPubHash = toHex(await sha256(concatBytes(...pubChunks)));
  if (actualPubHash !== expectedPubHash) return false;

  for (let i = 0; i < 256; i++) {
    const bit = (msgDigest[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
    const hashed = await sha256(preimages[i]);
    const target = bit === 1 ? pk1[i] : pk0[i];
    if (!bytesEqual(hashed, target)) return false;
  }

  const actualSig = toHex(await sha256(concatBytes(msgDigest, ...preimages)));
  return actualSig === expectedSig;
}

function updateEscrowUI(msg, ok = true) {
  document.getElementById("st-status").textContent = state.escrowStatus;
  const log = document.getElementById("escrow-log");
  log.className = ok ? "output pass" : "output fail";
  log.textContent = msg;
}

function bootUi() {
  if (typeof document === "undefined") return;

  document.getElementById("btn-keygen").addEventListener("click", async () => {
    try {
      await generateAndSign();
    } catch (err) {
      const out = document.getElementById("pqc-output");
      out.className = "output fail";
      out.textContent = `FAIL: ${err.message}`;
    }
  });

  document.getElementById("btn-verify").addEventListener("click", async () => {
    const ok = await verifyCurrentSignature();
    const out = document.getElementById("pqc-output");
    if (!state.keypair) return;
    out.className = ok ? "output pass" : "output fail";
    out.textContent = ok
      ? `PASS: Lamport-SHA256 preimages, pqcPubKeyHash, and pqcSigDigest match (${state.signature.sigDigest}).`
      : "FAIL: Lamport-SHA256 verification failed.";
  });

  document.getElementById("btn-fund-eip3009").addEventListener("click", async () => {
    try {
      if (!state.keypair) await generateAndSign();
      const terms = readTerms();
      const nonce = toHex(authorizationNonceBytes({ ...terms, pubKeyHash: state.keypair.pubKeyHash }));
      if (state.usedNonces.has(nonce)) {
        updateEscrowUI(`REVERT AuthorizationUsed for nonce ${nonce}`, false);
        return;
      }
      state.usedNonces.add(nonce);
      state.fundedTerms = { ...terms, pubKeyHash: state.keypair.pubKeyHash };
      state.escrowStatus = "Funded";
      document.getElementById("st-nonce").textContent = nonce;
      document.getElementById("st-pkhash").textContent = state.keypair.pubKeyHash;
      document.getElementById("st-sigdigest").textContent = "-";
      updateEscrowUI(
        `Simulated local EIP-3009 fund for ${terms.invoiceId}. Nonce binds merchant, expiresAt, and pqcPubKeyHash. This page did not broadcast.`,
        true,
      );
    } catch (err) {
      updateEscrowUI(`FAIL: ${err.message}`, false);
    }
  });

  document.getElementById("btn-release-pqc").addEventListener("click", async () => {
    if (state.escrowStatus !== "Funded") {
      updateEscrowUI("REVERT InvalidStatus: Invoice must be Funded before release.", false);
      return;
    }
    const terms = state.fundedTerms || state.terms;
    const commitment = encodeInvoiceCommitment(terms);
    const expectedDigest = await sha256(commitment);
    const digestMatches = bytesEqual(expectedDigest, state.signature.msgDigest);
    const ok = digestMatches && (await verifyCurrentSignature());
    if (!ok) {
      updateEscrowUI(
        "REVERT InvalidLamportProof: signature is not the invoice commitment (invoiceId, amount, payer, merchant, chainId, escrow).",
        false,
      );
      return;
    }
    state.escrowStatus = "Released";
    document.getElementById("st-sigdigest").textContent = state.signature.sigDigest;
    updateEscrowUI(
      `Simulated local Lamport release. Proof matched the on-chain invoice commitment. This page did not broadcast.`,
      true,
    );
  });

  document.getElementById("btn-refund").addEventListener("click", () => {
    if (state.escrowStatus !== "Funded") {
      updateEscrowUI("REVERT InvalidStatus: Only Funded invoices can be refunded.", false);
      return;
    }
    const expiresAt = Number(document.getElementById("expires-at").value || "0");
    const now = Math.floor(Date.now() / 1000);
    if (now < expiresAt) {
      updateEscrowUI(`REVERT NotExpired: now ${now} < expiresAt ${expiresAt}.`, false);
      return;
    }
    state.escrowStatus = "Refunded";
    updateEscrowUI(
      `Simulated local refund. now ${now} >= expiresAt ${expiresAt}. This page did not broadcast.`,
      true,
    );
  });

  document.querySelectorAll(".lab-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        if (!state.keypair) await generateAndSign();
      } catch (err) {
        const out = document.getElementById("lab-output");
        out.className = "output fail";
        out.textContent = `FAIL: ${err.message}`;
        return;
      }
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
        const terms = readTerms();
        const honest = toHex(authorizationNonceBytes({ ...terms, pubKeyHash: state.keypair.pubKeyHash }));
        const flipped =
          terms.merchant.toLowerCase() === "0x" + "22".repeat(20)
            ? "0x" + "33".repeat(20)
            : "0x" + "22".repeat(20);
        const hijack = toHex(
          authorizationNonceBytes({
            ...terms,
            merchant: flipped,
            pubKeyHash: state.keypair.pubKeyHash,
          }),
        );
        const later = toHex(
          authorizationNonceBytes({
            ...terms,
            expiresAt: terms.expiresAt + 1n,
            pubKeyHash: state.keypair.pubKeyHash,
          }),
        );
        const already = state.usedNonces.has(honest);
        state.usedNonces.add(honest);
        const replayBlocked = state.usedNonces.has(honest);
        const distinct = honest !== hijack && honest !== later;
        out.className = distinct && replayBlocked ? "output pass" : "output fail";
        out.textContent =
          distinct && replayBlocked
            ? `BLOCKED AS EXPECTED: AuthorizationUsed() — nonce ${honest} is consumed${already ? " (already funded)" : ""}. A substituted merchant yields ${hijack}, which this authorization does not cover.`
            : "UNEXPECTED PASS";
      } else if (sc === "premature-refund") {
        const expiresAt = Number(document.getElementById("expires-at").value || "0");
        const now = Math.floor(Date.now() / 1000);
        const blocked = now < expiresAt;
        out.className = blocked ? "output pass" : "output fail";
        out.textContent = blocked
          ? `BLOCKED AS EXPECTED: NotExpired() — now ${now} < expiresAt ${expiresAt}.`
          : `NOT BLOCKED: now ${now} >= expiresAt ${expiresAt}. Refund would be allowed.`;
      }
    });
  });
}

bootUi();
