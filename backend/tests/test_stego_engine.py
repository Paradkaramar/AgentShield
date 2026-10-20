# backend/tests/test_stego_engine.py
"""Comprehensive Unit Tests for AgentShield Stego Engine & Forensic Inspection."""

import pytest
import io
import os
import base64
from PIL import Image
from app.jarvis.cyber_tools.stego_engine import (
    encode_stego_message, decode_stego_message, inspect_image_and_exif
)



@pytest.fixture
def clean_rgb_image():
    """Generates an in-memory 80x80 clean RGB test image."""
    img = Image.new("RGB", (80, 80), color=(128, 64, 32))
    # Draw some gradient/variance to simulate natural pixel distributions
    pixels = img.load()
    for y in range(80):
        for x in range(80):
            pixels[x, y] = ((x * 3) % 256, (y * 3) % 256, (x + y) % 256)
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    return bio.getvalue()


@pytest.fixture
def clean_image_base64(clean_rgb_image):
    b64 = base64.b64encode(clean_rgb_image).decode("ascii")
    return f"data:image/png;base64,{b64}"


def test_stego_encode_and_decode_roundtrip(clean_rgb_image):
    secret = "AgentShield Alpha Directive: Zero-Trust Active 2026."
    res = encode_stego_message(clean_rgb_image, secret)
    assert res["success"] is True
    assert "data:image/png;base64," in res["image_data_uri"]
    assert res["carrier_tamper_safe"] is True
    assert res["payload_sha256"] is not None

    # Decode from generated data URI
    decode_res = decode_stego_message(res["image_data_uri"])
    assert decode_res["detected"] is True
    assert decode_res["format"] == "AgentShield-Secure-LSB"
    assert decode_res["integrity_verified"] is True
    assert decode_res["message"] == secret
    assert decode_res["payload_sha256"] == res["payload_sha256"]


def test_stego_encode_with_password(clean_rgb_image):
    secret = "Top Secret Classification: DEFCON 1."
    password = "CorrectHorseBatteryStaple2026!"

    res = encode_stego_message(clean_rgb_image, secret, password=password)
    assert res["is_encrypted"] is True

    # Decoding with wrong password produces scrambled output
    wrong_pass_decode = decode_stego_message(res["image_data_uri"], password="WrongPassword")
    assert wrong_pass_decode["detected"] is True
    assert wrong_pass_decode["message"] != secret

    # Decoding with correct password extracts original plaintext
    correct_decode = decode_stego_message(res["image_data_uri"], password=password)
    assert correct_decode["detected"] is True
    assert correct_decode["message"] == secret


def test_stego_legacy_cyberjarvis_delimiter_compatibility():
    """Verify decoding images encoded with Cyber-Jarvis legacy '11111111' delimiter format."""
    img = Image.new("RGB", (30, 30), color=(50, 50, 50))
    message = "CYBER_JARVIS_LEGACY_PAYLOAD"
    binary_msg = "".join(f"{ord(c):08b}" for c in message) + "11111111"  # Legacy 8-bit delimiter

    pixels = img.load()
    idx = 0
    w, h = img.size
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            if idx < len(binary_msg):
                r = (r & ~1) | int(binary_msg[idx])
                idx += 1
            if idx < len(binary_msg):
                g = (g & ~1) | int(binary_msg[idx])
                idx += 1
            if idx < len(binary_msg):
                b = (b & ~1) | int(binary_msg[idx])
                idx += 1
            pixels[x, y] = (r, g, b)

    bio = io.BytesIO()
    img.save(bio, format="PNG")

    res = decode_stego_message(bio.getvalue())
    assert res["detected"] is True
    assert res["format"] == "Legacy-CyberJarvis-LSB"
    assert res["message"] == message


def test_stego_capacity_overflow_check():
    """Verify that attempting to encode an oversized payload raises ValueError."""
    tiny_img = Image.new("RGB", (4, 4), color=(0, 0, 0))  # Only 4x4x3 = 48 bits capacity
    bio = io.BytesIO()
    tiny_img.save(bio, format="PNG")

    large_secret = "This text is definitely too large to fit in a 4x4 pixel image carrier!"
    with pytest.raises(ValueError) as exc:
        encode_stego_message(bio.getvalue(), large_secret)
    assert "exceeds image capacity" in str(exc.value)


def test_inspect_clean_image_and_entropy():
    # Solid/smooth clean image
    clean_img = Image.new("RGB", (60, 60), color=(120, 60, 40))
    bio = io.BytesIO()
    clean_img.save(bio, format="PNG")
    info = inspect_image_and_exif(bio.getvalue())
    assert info["width"] == 60
    assert info["height"] == 60
    assert "lsb_entropy" in info
    assert info["lsb_entropy"]["average"] == 0.0
    assert info["stego_payload"]["detected"] is False
    assert info["forensic_status"] == "CLEAN"


def test_inspect_stego_image_detects_payload(clean_rgb_image):
    encoded = encode_stego_message(clean_rgb_image, "Secret intelligence data.")
    info = inspect_image_and_exif(encoded["image_data_uri"])
    assert info["stego_payload"]["detected"] is True
    assert info["forensic_status"] == "CONFIRMED_STEGANOGRAPHY"
    assert any("Confirmed hidden steganographic payload" in r for r in info["risk_factors"])


def test_invalid_image_input():
    with pytest.raises(Exception):
        decode_stego_message(b"not_an_image_file_bytes")
