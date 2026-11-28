from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from pqc_verifier import (
    LamportSignature,
    authorization_nonce,
    build_invoice_commitment,
    generate_lamport_keypair,
    invoice_id_to_bytes32,
    keccak256,
    sign_message,
    verify_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MERCHANT_A = "0x1111111111111111111111111111111111111111"
MERCHANT_B = "0x2222222222222222222222222222222222222222"
PAYER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ESCROW = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CHAIN_ID = 44005


def _commit(invoice_id, amount, merchant, **kwargs):
    return build_invoice_commitment(
        invoice_id,
        amount,
        merchant,
        payer=kwargs.get("payer", PAYER),
        chain_id=kwargs.get("chain_id", CHAIN_ID),
        escrow=kwargs.get("escrow", ESCROW),
    )


def test_keygen_deterministic_with_seed():
    kp1 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000001")
    kp2 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000001")
    assert kp1.pub_key_hash == kp2.pub_key_hash
    assert len(kp1.pk0) == 256
    assert len(kp1.pk1) == 256
    assert kp1.pub_key_hash.startswith("0x") and len(kp1.pub_key_hash) == 66


def test_sign_and_verify_invoice_commitment():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000002")
    payload = _commit("inv-001", 5_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, sig) is True


def test_tampered_message_fails_verification():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000003")
    payload = _commit("inv-002", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    tampered = _commit("inv-002", 2_000_000, MERCHANT_A)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, tampered, sig) is False


def test_wrong_pub_key_hash_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000004")
    payload = _commit("inv-003", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, "0x" + "00" * 32, payload, sig) is False


def test_corrupted_preimage_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000005")
    payload = _commit("inv-004", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    bad_preimages = list(sig.revealed_preimages)
    bad_preimages[0] = b"\x00" * 32
    bad_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=tuple(bad_preimages),
        sig_digest=sig.sig_digest,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, bad_sig) is False


def test_invalid_commitment_inputs_raise():
    with pytest.raises(ValueError):
        _commit("inv-005", 0, MERCHANT_A)
    with pytest.raises(ValueError):
        _commit("inv-005", 100, "0x1234")


@pytest.mark.parametrize("index", [0, 127, 255])
def test_single_bit_flip_in_preimage_rejected(index: int):
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000006")
    payload = _commit("inv-bitflip", 3_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    tampered = list(sig.revealed_preimages)
    flipped = bytearray(tampered[index])
    flipped[0] ^= 0x01
    tampered[index] = bytes(flipped)
    bad_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=tuple(tampered),
        sig_digest=sig.sig_digest,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, bad_sig) is False


def test_tampered_message_digest_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000007")
    payload = _commit("inv-msg-digest", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    last_char = "0" if sig.message_digest[-1] != "0" else "1"
    bad_sig = LamportSignature(
        message_digest=sig.message_digest[:-1] + last_char,
        revealed_preimages=sig.revealed_preimages,
        sig_digest=sig.sig_digest,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, bad_sig) is False


def test_tampered_sig_digest_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000008")
    payload = _commit("inv-sig-digest", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    last_char = "0" if sig.sig_digest[-1] != "0" else "1"
    bad_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=sig.revealed_preimages,
        sig_digest=sig.sig_digest[:-1] + last_char,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, bad_sig) is False


def test_malformed_preimage_count_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000009")
    payload = _commit("inv-preimage-len", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    short_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=sig.revealed_preimages[:-1],
        sig_digest=sig.sig_digest,
    )
    long_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=sig.revealed_preimages + (b"\x00" * 32,),
        sig_digest=sig.sig_digest,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, short_sig) is False
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, long_sig) is False


def test_malformed_public_key_length_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000010")
    payload = _commit("inv-pk-len", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0[:-1], kp.pk1, kp.pub_key_hash, payload, sig) is False
    assert verify_signature(kp.pk0, kp.pk1[:-1], kp.pub_key_hash, payload, sig) is False


def test_malformed_preimage_byte_length_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000011")
    payload = _commit("inv-preimage-bytes", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    bad_preimages = list(sig.revealed_preimages)
    bad_preimages[10] = bad_preimages[10][:-1]
    bad_sig = LamportSignature(
        message_digest=sig.message_digest,
        revealed_preimages=tuple(bad_preimages),
        sig_digest=sig.sig_digest,
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, bad_sig) is False


def test_cross_escrow_replay_rejected_different_invoice_id():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000012")
    payload_a = _commit("inv-escrow-A", 5_000_000, MERCHANT_A)
    payload_b = _commit("inv-escrow-B", 5_000_000, MERCHANT_A)
    sig_a = sign_message(kp, payload_a)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload_b, sig_a) is False


def test_cross_escrow_replay_rejected_different_merchant():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000013")
    payload_a = _commit("inv-shared", 5_000_000, MERCHANT_A)
    payload_b = _commit("inv-shared", 5_000_000, MERCHANT_B)
    sig_a = sign_message(kp, payload_a)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload_b, sig_a) is False


def test_cross_keypair_substitution_rejected():
    kp1 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000014")
    kp2 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000015")
    payload = _commit("inv-cross-kp", 2_500_000, MERCHANT_A)
    sig1 = sign_message(kp1, payload)
    assert verify_signature(kp2.pk0, kp2.pk1, kp2.pub_key_hash, payload, sig1) is False


@pytest.mark.parametrize("bad_amount", [0, -1, -1_000_000])
def test_zero_and_negative_amount_rejected(bad_amount: int):
    with pytest.raises(ValueError, match="positive"):
        _commit("inv-neg", bad_amount, MERCHANT_A)


@pytest.mark.parametrize(
    "bad_merchant",
    [
        "",
        "1111111111111111111111111111111111111111",
        "0x1234",
        "0x" + "11" * 21,
    ],
)
def test_malformed_merchant_addresses_rejected(bad_merchant: str):
    with pytest.raises(ValueError, match="20-byte hex address"):
        _commit("inv-addr", 1_000_000, bad_merchant)


def test_canonical_digest_determinism_and_case_normalization():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000016")
    lower = _commit("inv-canon", 4_200_000, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
    upper = _commit("inv-canon", 4_200_000, "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
    assert lower == upper
    sig1 = sign_message(kp, lower)
    sig2 = sign_message(kp, upper)
    assert sig1.message_digest == sig2.message_digest
    assert sig1.sig_digest == sig2.sig_digest


def test_keccak256_matches_ethereum_empty_and_hello():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"hello").hex() == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"


def test_commitment_binds_payer_chain_and_escrow():
    base = _commit("inv-bind", 5_000_000, MERCHANT_A)
    assert base != _commit("inv-bind", 5_000_000, MERCHANT_A, payer=MERCHANT_B)
    assert base != _commit("inv-bind", 5_000_000, MERCHANT_A, chain_id=1)
    assert base != _commit("inv-bind", 5_000_000, MERCHANT_A, escrow=MERCHANT_B)
    short_id = invoice_id_to_bytes32("inv-bind")
    explicit = _commit(short_id, 5_000_000, MERCHANT_A)
    assert base == explicit
    assert base == _commit("0x" + short_id.hex(), 5_000_000, MERCHANT_A)


def test_signed_digest_is_sha256_of_abi_commitment():
    payload = _commit(bytes.fromhex("11" * 32), 5_000_000, MERCHANT_A)
    assert len(payload) == 192
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000017")
    sig = sign_message(kp, payload)
    assert sig.message_digest == "0x" + hashlib.sha256(payload).hexdigest()
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, sig) is True


def test_authorization_nonce_binds_relayer_fields():
    invoice = bytes.fromhex("22" * 32)
    pk = "0x" + "44" * 32
    nonce = authorization_nonce(ESCROW, invoice, MERCHANT_A, 3600, pk)
    swapped_merchant = authorization_nonce(ESCROW, invoice, MERCHANT_B, 3600, pk)
    swapped_expiry = authorization_nonce(ESCROW, invoice, MERCHANT_A, 3601, pk)
    swapped_pk = authorization_nonce(ESCROW, invoice, MERCHANT_A, 3600, "0x" + "55" * 32)
    assert len({nonce, swapped_merchant, swapped_expiry, swapped_pk}) == 4
    assert nonce == authorization_nonce(ESCROW, "0x" + invoice.hex(), MERCHANT_A.upper(), 3600, pk)


def test_abi_words_match_static_cast_vector():
    # cast abi-encode "f(address,bytes32,address,uint64,bytes32)" of the fixed words below.
    encoded = (
        bytes.fromhex("11" * 20).rjust(32, b"\x00")
        + bytes.fromhex("22" * 32)
        + bytes.fromhex("33" * 20).rjust(32, b"\x00")
        + (3600).to_bytes(32, "big")
        + bytes.fromhex("44" * 32)
    )
    assert keccak256(encoded).hex() == authorization_nonce(
        "0x" + "11" * 20,
        bytes.fromhex("22" * 32),
        "0x" + "33" * 20,
        3600,
        "0x" + "44" * 32,
    )[2:]
    commitment = build_invoice_commitment(
        bytes.fromhex("11" * 32),
        5_000_000,
        "0x" + "33" * 20,
        payer="0x" + "22" * 20,
        chain_id=44005,
        escrow="0x" + "44" * 20,
    )
    assert commitment == (
        bytes.fromhex("11" * 32)
        + (5_000_000).to_bytes(32, "big")
        + bytes.fromhex("22" * 20).rjust(32, b"\x00")
        + bytes.fromhex("33" * 20).rjust(32, b"\x00")
        + (44005).to_bytes(32, "big")
        + bytes.fromhex("44" * 20).rjust(32, b"\x00")
    )


def test_chain_44005_deploy_config_and_dry_run_validation():
    foundry_toml = (REPO_ROOT / "contracts" / "foundry.toml").read_text(encoding="utf-8")
    deploy_sol = (REPO_ROOT / "contracts" / "script" / "Deploy.s.sol").read_text(encoding="utf-8")
    deploy_sh = (REPO_ROOT / "scripts" / "deploy_aevum.sh").read_text(encoding="utf-8")

    assert 'evm_version = "shanghai"' in foundry_toml
    assert 'aevum = "https://rpc-test.qday.info"' in foundry_toml
    assert "0x456569838f1d43009A91ebA4263147Afd7233483" in deploy_sol
    assert "--dry-run" in deploy_sh
    assert "https://rpc-test.qday.info" in deploy_sh
