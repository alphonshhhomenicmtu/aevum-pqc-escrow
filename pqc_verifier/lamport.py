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


# Keccak-f[1600] round constants and ρ offsets. Pad byte is 0x01 (Keccak-256), not NIST SHA3.
_KECCAK_RC = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = (1 << 64) - 1


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: list[int]) -> None:
    for round_const in _KECCAK_RC:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)
        ]
        for x in range(5):
            mixed = columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= mixed
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], _KECCAK_ROT[x][y])
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    rotated[x + 5 * y]
                    ^ ((~rotated[((x + 1) % 5) + 5 * y]) & rotated[((x + 2) % 5) + 5 * y])
                ) & _MASK64
        state[0] = (state[0] ^ round_const) & _MASK64


def keccak256(data: bytes) -> bytes:
    """Ethereum keccak256. hashlib.sha3_256 is a different padding and must not be used."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while (len(padded) % rate) != rate - 1:
        padded.append(0)
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : (lane + 1) * 8], "little")
        _keccak_f(state)

    out = bytearray()
    for lane in range(4):
        out += state[lane].to_bytes(8, "little")
    return bytes(out)


def _word_uint(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _parse_address(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(("0x", "0X")) or len(value) != 42:
        raise ValueError(f"{field} must be a 20-byte hex address")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{field} must be a 20-byte hex address") from exc
    if len(raw) != 20:
        raise ValueError(f"{field} must be a 20-byte hex address")
    return raw


def _word_address(value: str, field: str) -> bytes:
    return b"\x00" * 12 + _parse_address(value, field)


def _parse_bytes32(value: str | bytes, field: str) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError(f"{field} must be 32 bytes")
        return value
    if not isinstance(value, str) or not value.startswith(("0x", "0X")) or len(value) != 66:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must be a 32-byte hex string")
    return raw


def invoice_id_to_bytes32(invoice_id: str | bytes) -> bytes:
    """Match the escrow: a 0x+64 hex id is the bytes32, otherwise keccak256(utf-8)."""
    if isinstance(invoice_id, bytes):
        if len(invoice_id) != 32:
            raise ValueError("invoice id must be 32 bytes")
        return invoice_id
    if not isinstance(invoice_id, str) or invoice_id == "":
        raise ValueError("invoice id must be a non-empty string or 32 bytes")
    if invoice_id.startswith(("0x", "0X")) and len(invoice_id) == 66:
        return _parse_bytes32(invoice_id, "invoice id")
    return keccak256(invoice_id.encode("utf-8"))


def _require_uint(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**256:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def authorization_nonce(
    escrow: str,
    invoice_id: str | bytes,
    *,
    payer: str,
    merchant: str,
    amount: int,
    expires_at: int,
    pqc_pub_key_hash: str | bytes,
    chain_id: int,
) -> str:
    """keccak256(abi.encode(chainId, escrow, invoiceId, payer, merchant, amount, expiresAt, pqcPubKeyHash))."""
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("amount must be positive")
    chain = _require_uint(chain_id, "chain_id")
    expires = _require_uint(expires_at, "expires_at")
    encoded = b"".join(
        (
            _word_uint(chain),
            _word_address(escrow, "escrow"),
            invoice_id_to_bytes32(invoice_id),
            _word_address(payer, "payer"),
            _word_address(merchant, "merchant"),
            _word_uint(amount),
            _word_uint(expires),
            _parse_bytes32(pqc_pub_key_hash, "pqc_pub_key_hash"),
        )
    )
    return "0x" + keccak256(encoded).hex()


def build_invoice_commitment(
    invoice_id: str | bytes,
    amount_tusd8: int,
    merchant: str,
    *,
    payer: str,
    chain_id: int,
    escrow: str,
) -> bytes:
    """abi.encode(invoiceId, amount, payer, merchant, chainId, escrow). sign_message sha256s these bytes."""
    if isinstance(amount_tusd8, bool) or not isinstance(amount_tusd8, int) or amount_tusd8 <= 0:
        raise ValueError("amount_tusd8 must be positive")
    chain = _require_uint(chain_id, "chain_id")
    return b"".join(
        (
            invoice_id_to_bytes32(invoice_id),
            _word_uint(amount_tusd8),
            _word_address(payer, "payer"),
            _word_address(merchant, "merchant"),
            _word_uint(chain),
            _word_address(escrow, "escrow"),
        )
    )
