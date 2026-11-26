from __future__ import annotations

import pytest

from pqc_verifier import (
    LamportSignature,
    build_invoice_commitment,
    generate_lamport_keypair,
    sign_message,
    verify_signature,
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
    payload = build_invoice_commitment(
        "inv-001", 5_000_000, "0x1111111111111111111111111111111111111111"
    )
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, sig) is True


def test_tampered_message_fails_verification():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000003")
    payload = build_invoice_commitment(
        "inv-002", 1_000_000, "0x1111111111111111111111111111111111111111"
    )
    sig = sign_message(kp, payload)
    tampered = build_invoice_commitment(
        "inv-002", 2_000_000, "0x1111111111111111111111111111111111111111"
    )
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, tampered, sig) is False


def test_wrong_pub_key_hash_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000004")
    payload = build_invoice_commitment(
        "inv-003", 1_000_000, "0x1111111111111111111111111111111111111111"
    )
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, "0x" + "00" * 32, payload, sig) is False


def test_corrupted_preimage_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000005")
    payload = build_invoice_commitment(
        "inv-004", 1_000_000, "0x1111111111111111111111111111111111111111"
    )
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
        build_invoice_commitment("inv-005", 0, "0x1111111111111111111111111111111111111111")
    with pytest.raises(ValueError):
        build_invoice_commitment("inv-005", 100, "0x1234")
