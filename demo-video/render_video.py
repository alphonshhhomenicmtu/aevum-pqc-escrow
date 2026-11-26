#!/usr/bin/env python3
"""Render 1080p/30fps -14 LUFS English-voiceover demo video for Aevum PQC Invoice Escrow."""

from __future__ import annotations

import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

BASE = Path(__file__).resolve().parent
APP_DIR = BASE.parent
SHOTS = APP_DIR / "docs" / "screenshots"
OUT_MP4 = BASE / "aevum-pqc-demo-1080p.mp4"

SCENES = [
    (
        SHOTS / "01-overview.png",
        "1. Aevum PQC Invoice Escrow — Chain 44005 (Shanghai EVM) + tUSD8",
        "Welcome to Aevum PQC Invoice Escrow, built for QDay Aevum Testnet, Chain ID 44005, on the Shanghai EVM. "
        "Standard stablecoin checkouts rely solely on ECDSA signatures. We pair gasless tUSD8 EIP-3009 settlement "
        "with on-chain Post-Quantum Lamport-SHA256 verification.",
    ),
    (
        SHOTS / "02-lamport-keygen-verify.png",
        "2. Live Browser Lamport-SHA256 Keygen & Signature Verification",
        "First, in our live Web Console, the browser generates a 256-bit Lamport-SHA256 one-time keypair using WebCrypto, "
        "hashes the public key into pqcPubKeyHash, and signs the canonical tUSD8 invoice commitment to produce pqcSigDigest.",
    ),
    (
        SHOTS / "03-eip3009-escrow-flow.png",
        "3. Gasless EIP-3009 Fund + On-Chain Lamport Proof Release",
        "Next, a buyer funds the invoice gaslessly via tUSD8 receiveWithAuthorization, bound to an order-specific "
        "authorizationNonce. When delivery completes, the merchant calls releaseWithLamportProof, which verifies all "
        "256 SHA-256 preimages directly on-chain before releasing tUSD8.",
    ),
    (
        SHOTS / "04-quantum-breaker-lab.png",
        "4. Adversarial Quantum Breaker Lab — 4 Invariant Checks",
        "In the Adversarial Quantum Breaker Lab, we test four failure modes: flipping a single bit in a Lamport preimage, "
        "supplying a mismatched public key hash, replaying an EIP-3009 nonce, and attempting a premature refund. "
        "Every attack is deterministically blocked.",
    ),
    (
        SHOTS / "01-overview.png",
        "5. Verified: 8/8 Forge (Shanghai) | 6/6 Pytest | 0 Slither H/M",
        "The entire stack is verified offline and on QDay RPC: eight of eight Foundry Shanghai tests pass, "
        "six of six Python PQC tests pass, Slither reports zero high or medium findings, "
        "and our turnkey Chain 44005 deploy dry-run succeeds cleanly.",
    ),
]


def _run(cmd: list[str]) -> str:
    res = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return res.stdout + res.stderr


def _probe_duration(path: Path) -> float:
    out = _run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(path),
        ]
    )
    return float(out.strip())


def _annotate_slide(src_png: Path, dst_png: Path, banner: str) -> None:
    img = Image.open(src_png).convert("RGB").resize((1920, 1080), Image.Resampling.LANCZOS)
    draw = ImageDraw.Draw(img, "RGBA")
    draw.rectangle([(0, 1016), (1920, 1080)], fill=(7, 11, 20, 225))
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 28)
    except Exception:
        font = ImageFont.load_default()
    draw.text((36, 1032), banner, fill=(56, 189, 248, 255), font=font)
    img.save(dst_png)


def main() -> None:
    tmp_dir = BASE / "_tmp_build"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    segments: list[Path] = []

    for idx, (shot, banner, narration) in enumerate(SCENES):
        aiff = tmp_dir / f"seg_{idx}.aiff"
        wav_raw = tmp_dir / f"seg_{idx}_raw.wav"
        wav_norm = tmp_dir / f"seg_{idx}.wav"
        slide = tmp_dir / f"slide_{idx}.png"
        seg_mp4 = tmp_dir / f"seg_{idx}.mp4"

        _run(["say", "-v", "Daniel", "-r", "168", "-o", str(aiff), narration])
        _run(["ffmpeg", "-y", "-i", str(aiff), "-ar", "48000", "-ac", "1", str(wav_raw)])
        _run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(wav_raw),
                "-af",
                "apad=pad_dur=0.6,loudnorm=I=-14:TP=-1.5:LRA=11",
                "-ar",
                "48000",
                "-ac",
                "2",
                str(wav_norm),
            ]
        )
        dur = _probe_duration(wav_norm)
        _annotate_slide(shot, slide, banner)

        _run(
            [
                "ffmpeg",
                "-y",
                "-loop",
                "1",
                "-i",
                str(slide),
                "-i",
                str(wav_norm),
                "-c:v",
                "libx264",
                "-t",
                f"{dur:.3f}",
                "-r",
                "30",
                "-pix_fmt",
                "yuv420p",
                "-crf",
                "18",
                "-preset",
                "medium",
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-shortest",
                str(seg_mp4),
            ]
        )
        segments.append(seg_mp4)

    concat_txt = tmp_dir / "concat.txt"
    concat_txt.write_text("\n".join(f"file '{s.resolve()}'" for s in segments) + "\n", encoding="utf-8")

    raw_mp4 = tmp_dir / "raw_concat.mp4"
    _run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat_txt), "-c", "copy", str(raw_mp4)])
    _run(
        [
            "ffmpeg",
            "-y",
            "-i",
            str(raw_mp4),
            "-af",
            "loudnorm=I=-14:TP=-1.5:LRA=11",
            "-c:v",
            "copy",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            "-movflags",
            "+faststart",
            str(OUT_MP4),
        ]
    )

    for p in tmp_dir.glob("*"):
        p.unlink()
    tmp_dir.rmdir()
    print(f"Rendered {OUT_MP4} ({_probe_duration(OUT_MP4):.2f}s)")


if __name__ == "__main__":
    main()
