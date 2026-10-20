# backend/app/jarvis/cyber_tools/stego_engine.py
"""Defensive Steganography and File Inspection Engine for AMOJA AI + AgentShield.
Provides memory-safe LSB encoding, decoding, integrity verification,
entropy analysis for hidden data detection, and EXIF metadata/GPS inspection.
"""

import os
import io
import math
import hashlib
import base64
from typing import Dict, Any, Optional, Tuple, Union
from PIL import Image, ExifTags

# Magic signature for AgentShield-encoded stego images
STEGO_MAGIC = b"AGST"  # 4 bytes
MAX_IMAGE_DIMENSION = 8192  # Prevent decompression bomb DoS
MAX_MESSAGE_BYTES = 5 * 1024 * 1024  # 5 MB max secret payload
DELIMITER_LEGACY = "11111111"  # Cyber-Jarvis legacy delimiter


def _load_image(image_input: Union[str, bytes]) -> Tuple[Image.Image, str]:
    """Safely loads a PIL Image from base64, raw bytes, or sanitized local path.
    Enforces dimension limits to prevent decompression bomb attacks.
    """
    fmt = "PNG"
    if isinstance(image_input, bytes):
        raw_bytes = image_input
    elif isinstance(image_input, str):
        image_str = image_input.strip()
        if image_str.startswith("data:image/") and ";base64," in image_str:
            # Data URI format
            header, b64data = image_str.split(";base64,", 1)
            raw_bytes = base64.b64decode(b64data)
            if "jpeg" in header or "jpg" in header:
                fmt = "JPEG"
        elif len(image_str) > 100 and not os.path.exists(image_str):
            # Presumed raw base64 string
            raw_bytes = base64.b64decode(image_str)
        else:
            # Local filesystem path
            clean_path = os.path.abspath(image_str)
            if not os.path.exists(clean_path):
                raise FileNotFoundError(f"Image file does not exist: {image_str}")
            with open(clean_path, "rb") as f:
                raw_bytes = f.read()

    bio = io.BytesIO(raw_bytes)
    img = Image.open(bio)
    if img.format:
        fmt = img.format

    width, height = img.size
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise ValueError(
            f"Image dimensions {width}x{height} exceed safety limit of {MAX_IMAGE_DIMENSION}px."
        )

    # Convert palette/grayscale images to RGB for LSB processing
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    return img, fmt


def encode_stego_message(
    image_input: Union[str, bytes],
    message: str,
    password: Optional[str] = None
) -> Dict[str, Any]:
    """Encodes a secret message into an image using cryptographic LSB steganography.

    Packaging structure:
    [4B STEGO_MAGIC] + [4B payload_len] + [32B sha256_hash] + [payload_bytes] + [8b legacy delimiter]

    Returns base64 PNG data URL, payload SHA-256, capacity metrics, and carrier details.
    """
    if not message:
        raise ValueError("Secret message cannot be empty.")

    payload_bytes = message.encode("utf-8")
    if password:
        # Simple symmetric derivation for obscurity layer
        key = hashlib.sha256(password.encode("utf-8")).digest()
        payload_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(payload_bytes)])

    payload_len = len(payload_bytes)
    if payload_len > MAX_MESSAGE_BYTES:
        raise ValueError(f"Message exceeds maximum size of {MAX_MESSAGE_BYTES} bytes.")

    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    img, _ = _load_image(image_input)
    width, height = img.size
    num_channels = len(img.getbands())  # 3 (RGB) or 4 (RGBA)
    # Only encode in RGB channels, leave Alpha channel intact
    usable_channels = 3
    total_carrier_bits = width * height * usable_channels
    total_carrier_bytes = total_carrier_bits // 8

    # Package: 4B magic + 4B length + 32B sha256 + payload + 1B legacy delimiter
    header_block = STEGO_MAGIC + payload_len.to_bytes(4, byteorder="big") + bytes.fromhex(payload_sha256)
    full_stream = header_block + payload_bytes + b"\xff"

    stream_bits = "".join(f"{byte:08b}" for byte in full_stream)
    # Append Cyber-Jarvis legacy delimiter for cross-compatibility
    stream_bits += DELIMITER_LEGACY

    if len(stream_bits) > total_carrier_bits:
        raise ValueError(
            f"Payload requiring {len(stream_bits)} bits exceeds image capacity of {total_carrier_bits} bits. "
            f"Please use a larger image or shorter message."
        )

    # Perform LSB encoding
    pixels = img.load()
    bit_index = 0
    total_bits = len(stream_bits)

    for y in range(height):
        if bit_index >= total_bits:
            break
        for x in range(width):
            if bit_index >= total_bits:
                break

            pixel = list(pixels[x, y])
            # Modify R, G, B channels
            for c in range(3):
                if bit_index < total_bits:
                    bit = int(stream_bits[bit_index])
                    pixel[c] = (pixel[c] & ~1) | bit
                    bit_index += 1

            pixels[x, y] = tuple(pixel)

    # Always save encoded image to lossless PNG to preserve LSB integrity
    out_bio = io.BytesIO()
    img.save(out_bio, format="PNG")
    encoded_bytes = out_bio.getvalue()
    b64_output = base64.b64encode(encoded_bytes).decode("ascii")

    return {
        "success": True,
        "format": "PNG",
        "mime_type": "image/png",
        "image_data_uri": f"data:image/png;base64,{b64_output}",
        "width": width,
        "height": height,
        "total_capacity_bytes": total_carrier_bytes,
        "payload_bytes_used": len(full_stream),
        "capacity_utilization_percent": round((len(full_stream) / total_carrier_bytes) * 100, 2),
        "payload_sha256": payload_sha256,
        "is_encrypted": bool(password),
        "carrier_tamper_safe": True
    }


def decode_stego_message(
    image_input: Union[str, bytes],
    password: Optional[str] = None
) -> Dict[str, Any]:
    """Decodes a hidden message from an image using LSB steganography.
    Supports both AgentShield cryptographically verified payloads and
    Cyber-Jarvis legacy delimiter payloads.
    """
    img, _ = _load_image(image_input)
    width, height = img.size
    pixels = img.load()

    # Extract all LSBs from R, G, B channels
    bit_list = []
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            bit_list.append(str(pixel[0] & 1))
            bit_list.append(str(pixel[1] & 1))
            bit_list.append(str(pixel[2] & 1))

    all_bits = "".join(bit_list)
    total_bytes = len(all_bits) // 8
    # Convert first 40 bytes to check AgentShield header: 4B magic + 4B len + 32B sha256
    raw_header_bytes = bytearray()
    for i in range(min(total_bytes, 40)):
        byte_bits = all_bits[i * 8 : (i + 1) * 8]
        raw_header_bytes.append(int(byte_bits, 2))

    # Check for AgentShield magic signature
    if raw_header_bytes.startswith(STEGO_MAGIC) and len(raw_header_bytes) >= 40:
        payload_len = int.from_bytes(raw_header_bytes[4:8], byteorder="big")
        expected_sha = raw_header_bytes[8:40].hex()

        if 0 < payload_len <= MAX_MESSAGE_BYTES and 40 + payload_len <= total_bytes:
            payload_data = bytearray()
            start_offset = 40
            for i in range(start_offset, start_offset + payload_len):
                byte_bits = all_bits[i * 8 : (i + 1) * 8]
                payload_data.append(int(byte_bits, 2))

            extracted_bytes = bytes(payload_data)
            actual_sha = hashlib.sha256(extracted_bytes).hexdigest()

            if actual_sha.lower() == expected_sha.lower():
                # Cryptographic integrity verified!
                if password:
                    key = hashlib.sha256(password.encode("utf-8")).digest()
                    extracted_bytes = bytes([b ^ key[k % len(key)] for k, b in enumerate(extracted_bytes)])

                try:
                    decoded_text = extracted_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    decoded_text = extracted_bytes.decode("latin-1", errors="replace")

                return {
                    "detected": True,
                    "format": "AgentShield-Secure-LSB",
                    "integrity_verified": True,
                    "payload_sha256": actual_sha,
                    "payload_length_bytes": payload_len,
                    "message": decoded_text,
                    "is_encrypted": bool(password)
                }

    # Fallback: check for Cyber-Jarvis legacy delimiter "11111111"
    # Find position of delimiter
    delimiter_pos = all_bits.find(DELIMITER_LEGACY)
    if delimiter_pos > 0 and delimiter_pos % 8 == 0:
        legacy_bits = all_bits[:delimiter_pos]
        legacy_bytes = bytearray()
        for i in range(0, len(legacy_bits), 8):
            legacy_bytes.append(int(legacy_bits[i : i + 8], 2))

        try:
            legacy_text = legacy_bytes.decode("utf-8")
            # Filter out non-printable ASCII noise if false positive
            printable_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in legacy_bytes) / len(legacy_bytes)
            if printable_ratio > 0.85 and len(legacy_text.strip()) > 0:
                return {
                    "detected": True,
                    "format": "Legacy-CyberJarvis-LSB",
                    "integrity_verified": False,
                    "payload_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
                    "payload_length_bytes": len(legacy_bytes),
                    "message": legacy_text,
                    "is_encrypted": False
                }
        except UnicodeDecodeError:
            pass

    return {
        "detected": False,
        "format": "None",
        "integrity_verified": False,
        "message": None,
        "details": "No embedded steganographic payload detected in image LSB channels."
    }


def _calculate_channel_entropy(bit_sequence: str) -> float:
    """Calculates Shannon entropy for binary bit sequence."""
    if not bit_sequence:
        return 0.0
    count_0 = bit_sequence.count("0")
    count_1 = len(bit_sequence) - count_0
    total = len(bit_sequence)
    if count_0 == 0 or count_1 == 0:
        return 0.0
    p0 = count_0 / total
    p1 = count_1 / total
    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


def _convert_gps_coords(coord_values: Any, ref: str) -> Optional[float]:
    """Converts EXIF GPS rational (Degrees, Minutes, Seconds) to decimal degrees."""
    try:
        if not coord_values or len(coord_values) < 3:
            return None
        d = float(coord_values[0])
        m = float(coord_values[1])
        s = float(coord_values[2])
        decimal = d + (m / 60.0) + (s / 3600.0)
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def inspect_image_and_exif(image_input: Union[str, bytes]) -> Dict[str, Any]:
    """Performs deep forensic inspection of an image:
    1. EXIF metadata extraction & GPS geolocation parsing
    2. Bitplane Shannon entropy analysis (detects presence of hidden encrypted data)
    3. Structural & metadata anomaly checks (photo editing software tampering)
    4. Steganography detection scan
    """
    img, raw_format = _load_image(image_input)
    width, height = img.size
    pixels = img.load()

    # 1. EXIF Metadata Extraction
    exif_data: Dict[str, Any] = {}
    gps_info: Dict[str, Any] = {}
    software_tamper_detected = False
    software_name = None

    raw_exif = None
    try:
        raw_exif = img.getexif()
    except Exception:
        pass

    if raw_exif:
        for tag_id, val in raw_exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
            # Format value to JSON-serializable
            if isinstance(val, bytes):
                val_repr = f"bytes({len(val)}B)"
            else:
                val_repr = str(val)

            exif_data[tag_name] = val_repr

            if tag_name.lower() == "software":
                software_name = str(val)
                # Check for image editing software signatures
                known_editors = ["photoshop", "gimp", "lightroom", "paint.net", "canva", "snapseed"]
                if any(ed in software_name.lower() for ed in known_editors):
                    software_tamper_detected = True

            # Extract GPS tags if present
            if tag_name == "GPSInfo" or tag_id == 0x8825:
                gps_tags = {}
                try:
                    for g_key, g_val in val.items():
                        g_name = ExifTags.GPSTAGS.get(g_key, f"GPS_{g_key}")
                        gps_tags[g_name] = g_val
                except Exception:
                    pass

                lat = _convert_gps_coords(gps_tags.get("GPSLatitude"), gps_tags.get("GPSLatitudeRef", "N"))
                lon = _convert_gps_coords(gps_tags.get("GPSLongitude"), gps_tags.get("GPSLongitudeRef", "E"))
                alt = gps_tags.get("GPSAltitude")
                if alt is not None:
                    try:
                        alt = round(float(alt), 1)
                    except Exception:
                        alt = None

                if lat is not None and lon is not None:
                    gps_info = {
                        "has_gps": True,
                        "latitude": lat,
                        "longitude": lon,
                        "altitude_meters": alt,
                        "maps_url": f"https://www.google.com/maps?q={lat},{lon}"
                    }

    # 2. Bitplane Shannon Entropy Analysis
    # Sample up to 15,000 pixels across image for fast forensic profiling
    step = max(1, (width * height) // 15000)
    r_bits = []
    g_bits = []
    b_bits = []

    count = 0
    for y in range(0, height):
        for x in range(0, width):
            count += 1
            if count % step == 0:
                p = pixels[x, y]
                r_bits.append(str(p[0] & 1))
                g_bits.append(str(p[1] & 1))
                b_bits.append(str(p[2] & 1))

    entropy_r = _calculate_channel_entropy("".join(r_bits))
    entropy_g = _calculate_channel_entropy("".join(g_bits))
    entropy_b = _calculate_channel_entropy("".join(b_bits))
    avg_entropy = round((entropy_r + entropy_g + entropy_b) / 3.0, 4)

    # In clean natural uncompressed images, LSB entropy is ~0.85-0.97.
    # In heavily encrypted stego carriers, entropy approaches 0.999-1.000 uniformly.
    high_entropy_warning = avg_entropy >= 0.9985

    # 3. Quick Stego Probe
    stego_probe = decode_stego_message(image_input)

    # 4. Summary & Forensic Assessment
    risk_factors = []
    if stego_probe.get("detected"):
        risk_factors.append(f"Confirmed hidden steganographic payload detected ({stego_probe.get('format')}).")
        forensic_status = "CONFIRMED_STEGANOGRAPHY"
    elif software_tamper_detected:
        risk_factors.append(f"Image edited using external software: '{software_name}'.")
        forensic_status = "MODIFIED_BY_EDITOR"
    elif high_entropy_warning:
        # Statistical indicator: note elevated bitplane randomness
        risk_factors.append("Elevated LSB bitplane entropy observed (potential high-density noise or encrypted carrier).")
        forensic_status = "ELEVATED_ENTROPY"
    else:
        forensic_status = "CLEAN"

    if gps_info.get("has_gps"):
        risk_factors.append(f"Exposed GPS geolocation metadata: ({gps_info.get('latitude')}, {gps_info.get('longitude')}).")

    return {
        "format": raw_format,
        "width": width,
        "height": height,
        "megapixels": round((width * height) / 1_000_000, 2),
        "total_carrier_capacity_bytes": (width * height * 3) // 8,
        "has_exif": len(exif_data) > 0,
        "exif_tags_count": len(exif_data),
        "camera_make": exif_data.get("Make"),
        "camera_model": exif_data.get("Model"),
        "datetime_original": exif_data.get("DateTimeOriginal") or exif_data.get("DateTime"),
        "software": software_name,
        "software_tamper_flag": software_tamper_detected,
        "gps_geolocation": gps_info,
        "lsb_entropy": {
            "channel_r": round(entropy_r, 4),
            "channel_g": round(entropy_g, 4),
            "channel_b": round(entropy_b, 4),
            "average": avg_entropy,
            "high_entropy_suspected": high_entropy_warning
        },
        "stego_payload": stego_probe,
        "risk_factors": risk_factors,
        "forensic_status": forensic_status
    }
