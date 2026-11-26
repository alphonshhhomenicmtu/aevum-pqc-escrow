from __future__ import annotations

from pathlib import Path

import pytest

from pqc_verifier import (
    LamportSignature,
    build_invoice_commitment,
    generate_lamport_keypair,
    sign_message,
    verify_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MERCHANT_A = "0x1111111111111111111111111111111111111111"
MERCHANT_B = "0x2222222222222222222222222222222222222222"


def test_keygen_deterministic_with_seed():
    kp1 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000001")
    kp2 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000001")
    assert kp1.pub_key_hash == kp2.pub_key_hash
    assert len(kp1.pk0) == 256
    assert len(kp1.pk1) == 256
    assert kp1.pub_key_hash.startswith("0x") and len(kp1.pub_key_hash) == 66


def test_sign_and_verify_invoice_commitment():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000002")
    payload = build_invoice_commitment("inv-001", 5_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload, sig) is True


def test_tampered_message_fails_verification():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000003")
    payload = build_invoice_commitment("inv-002", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    tampered = build_invoice_commitment("inv-002", 2_000_000, MERCHANT_A)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, tampered, sig) is False


def test_wrong_pub_key_hash_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000004")
    payload = build_invoice_commitment("inv-003", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0, kp.pk1, "0x" + "00" * 32, payload, sig) is False


def test_corrupted_preimage_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000005")
    payload = build_invoice_commitment("inv-004", 1_000_000, MERCHANT_A)
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
        build_invoice_commitment("inv-005", 0, MERCHANT_A)
    with pytest.raises(ValueError):
        build_invoice_commitment("inv-005", 100, "0x1234")


@pytest.mark.parametrize("index", [0, 127, 255])
def test_single_bit_flip_in_preimage_rejected(index: int):
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000006")
    payload = build_invoice_commitment("inv-bitflip", 3_000_000, MERCHANT_A)
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
    payload = build_invoice_commitment("inv-msg-digest", 1_000_000, MERCHANT_A)
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
    payload = build_invoice_commitment("inv-sig-digest", 1_000_000, MERCHANT_A)
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
    payload = build_invoice_commitment("inv-preimage-len", 1_000_000, MERCHANT_A)
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
    payload = build_invoice_commitment("inv-pk-len", 1_000_000, MERCHANT_A)
    sig = sign_message(kp, payload)
    assert verify_signature(kp.pk0[:-1], kp.pk1, kp.pub_key_hash, payload, sig) is False
    assert verify_signature(kp.pk0, kp.pk1[:-1], kp.pub_key_hash, payload, sig) is False


def test_malformed_preimage_byte_length_rejected():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000011")
    payload = build_invoice_commitment("inv-preimage-bytes", 1_000_000, MERCHANT_A)
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
    payload_a = build_invoice_commitment("inv-escrow-A", 5_000_000, MERCHANT_A)
    payload_b = build_invoice_commitment("inv-escrow-B", 5_000_000, MERCHANT_A)
    sig_a = sign_message(kp, payload_a)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload_b, sig_a) is False


def test_cross_escrow_replay_rejected_different_merchant():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000013")
    payload_a = build_invoice_commitment("inv-shared", 5_000_000, MERCHANT_A)
    payload_b = build_invoice_commitment("inv-shared", 5_000_000, MERCHANT_B)
    sig_a = sign_message(kp, payload_a)
    assert verify_signature(kp.pk0, kp.pk1, kp.pub_key_hash, payload_b, sig_a) is False


def test_cross_keypair_substitution_rejected():
    kp1 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000014")
    kp2 = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000015")
    payload = build_invoice_commitment("inv-cross-kp", 2_500_000, MERCHANT_A)
    sig1 = sign_message(kp1, payload)
    assert verify_signature(kp2.pk0, kp2.pk1, kp2.pub_key_hash, payload, sig1) is False


@pytest.mark.parametrize("bad_amount", [0, -1, -1_000_000])
def test_zero_and_negative_amount_rejected(bad_amount: int):
    with pytest.raises(ValueError, match="positive"):
        build_invoice_commitment("inv-neg", bad_amount, MERCHANT_A)


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
        build_invoice_commitment("inv-addr", 1_000_000, bad_merchant)


def test_canonical_digest_determinism_and_case_normalization():
    kp = generate_lamport_keypair(seed=b"aevum-test-seed-0000000000000016")
    lower = build_invoice_commitment("inv-canon", 4_200_000, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
    upper = build_invoice_commitment("inv-canon", 4_200_000, "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
    assert lower == upper
    sig1 = sign_message(kp, lower)
    sig2 = sign_message(kp, upper)
    assert sig1.message_digest == sig2.message_digest
    assert sig1.sig_digest == sig2.sig_digest


def test_chain_44005_deploy_config_and_dry_run_validation():
    foundry_toml = (REPO_ROOT / "contracts" / "foundry.toml").read_text(encoding="utf-8")
    deploy_sol = (REPO_ROOT / "contracts" / "script" / "Deploy.s.sol").read_text(encoding="utf-8")
    deploy_sh = (REPO_ROOT / "scripts" / "deploy_aevum.sh").read_text(encoding="utf-8")

    assert 'evm_version = "shanghai"' in foundry_toml
    assert 'aevum = "https://rpc-test.qday.info"' in foundry_toml
    assert "0x456569838f1d43009A91ebA4263147Afd7233483" in deploy_sol
    assert "--dry-run" in deploy_sh
    assert "https://rpc-test.qday.info" in deploy_sh
