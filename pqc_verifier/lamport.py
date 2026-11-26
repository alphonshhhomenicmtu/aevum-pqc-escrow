from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LamportKeypair:
    """Post-Quantum Lamport-SHA256 One-Time Signature keypair (256-bit security)."""

    sk0: tuple[bytes, ...]
    sk1: tuple[bytes, ...]
    pk0: tuple[bytes, ...]
    pk1: tuple[bytes, ...]
    pub_key_hash: str


@dataclass(frozen=True, slots=True)
class LamportSignature:
    """256-element Lamport-SHA256 signature and deterministic commitment digest."""

    message_digest: str
    revealed_preimages: tuple[bytes, ...]
    sig_digest: str


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _compute_pub_key_hash(pk0: tuple[bytes, ...], pk1: tuple[bytes, ...]) -> str:
    h = hashlib.sha256()
    for p0, p1 in zip(pk0, pk1, strict=True):
        h.update(p0)
        h.update(p1)
    return "0x" + h.hexdigest()


def generate_lamport_keypair(*, seed: bytes | None = None) -> LamportKeypair:
    """Generate a 256-bit Post-Quantum Lamport-SHA256 keypair."""
    sk0_list: list[bytes] = []
    sk1_list: list[bytes] = []
    pk0_list: list[bytes] = []
    pk1_list: list[bytes] = []

    master = seed if seed is not None else os.urandom(32)
    for idx in range(256):
        s0 = _sha256(master + idx.to_bytes(2, "big") + b"\x00")
        s1 = _sha256(master + idx.to_bytes(2, "big") + b"\x01")
        sk0_list.append(s0)
        sk1_list.append(s1)
        pk0_list.append(_sha256(s0))
        pk1_list.append(_sha256(s1))

    pk0 = tuple(pk0_list)
    pk1 = tuple(pk1_list)
    return LamportKeypair(
        sk0=tuple(sk0_list),
        sk1=tuple(sk1_list),
        pk0=pk0,
        pk1=pk1,
        pub_key_hash=_compute_pub_key_hash(pk0, pk1),
    )


def sign_message(keypair: LamportKeypair, message: bytes) -> LamportSignature:
    """Sign an arbitrary byte message with a one-time Lamport keypair."""
    msg_digest = _sha256(message)
    revealed: list[bytes] = []
    sig_hasher = hashlib.sha256()
    sig_hasher.update(msg_digest)

    for bit_idx in range(256):
        byte_val = msg_digest[bit_idx // 8]
        bit = (byte_val >> (7 - (bit_idx % 8))) & 1
        preimage = keypair.sk1[bit_idx] if bit == 1 else keypair.sk0[bit_idx]
        revealed.append(preimage)
        sig_hasher.update(preimage)

    return LamportSignature(
        message_digest="0x" + msg_digest.hex(),
        revealed_preimages=tuple(revealed),
        sig_digest="0x" + sig_hasher.hexdigest(),
    )


def verify_signature(
    pk0: tuple[bytes, ...],
    pk1: tuple[bytes, ...],
    expected_pub_key_hash: str,
    message: bytes,
    signature: LamportSignature,
) -> bool:
    """Verify a Lamport-SHA256 signature and its public-key commitment."""
    if len(pk0) != 256 or len(pk1) != 256 or len(signature.revealed_preimages) != 256:
        return False
    if _compute_pub_key_hash(pk0, pk1) != expected_pub_key_hash:
        return False

    msg_digest = _sha256(message)
    if "0x" + msg_digest.hex() != signature.message_digest:
        return False

    sig_hasher = hashlib.sha256()
    sig_hasher.update(msg_digest)

    for bit_idx in range(256):
        byte_val = msg_digest[bit_idx // 8]
        bit = (byte_val >> (7 - (bit_idx % 8))) & 1
        preimage = signature.revealed_preimages[bit_idx]
        expected_pk = pk1[bit_idx] if bit == 1 else pk0[bit_idx]
        if _sha256(preimage) != expected_pk:
            return False
        sig_hasher.update(preimage)

    return "0x" + sig_hasher.hexdigest() == signature.sig_digest


def build_invoice_commitment(invoice_id: str, amount_tusd8: int, merchant: str) -> bytes:
    """Build canonical domain-separated payload for PqcInvoiceEscrow attestation."""
    if amount_tusd8 <= 0:
        raise ValueError("amount_tusd8 must be positive")
    if not merchant.startswith("0x") or len(merchant) != 42:
        raise ValueError("merchant must be a 20-byte hex address")
    return f"AEVUM_TUSD8_INVOICE:{invoice_id}:{amount_tusd8}:{merchant.lower()}".encode("utf-8")
