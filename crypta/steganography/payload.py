"""
Binary payload framing specification for Crypta.
Handles packing, unpacking, magic header validation, version handling, and filename sanitization.
Version 2 specification incorporates AES-256-GCM salt and nonce parameters.
"""

import struct
from pathlib import Path
from typing import Tuple
from crypta.utils.constants import (
    MAGIC_BYTES,
    HEADER_VERSION,
    HEADER_VERSION_LEGACY,
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    SHA256_DIGEST_SIZE_BYTES,
    AES_GCM_TAG_SIZE_BYTES,
)


def calculate_framed_overhead(original_filename: str) -> int:
    """Calculate exact overhead in bytes for a given filename in Version 2 framed payload.

    Overhead includes:
    Magic (8B) + Version (1B) + Salt (16B) + Nonce (12B) + FnLen (2B) + Filename (N Bytes)
    + CiphertextLen (8B) + Inner SHA-256 (32B) + AES-GCM Auth Tag (16B)
    """
    clean_name = Path(original_filename).name
    fn_bytes = clean_name.encode("utf-8")
    header_overhead = (
        len(MAGIC_BYTES)
        + 1  # Version
        + SALT_SIZE_BYTES
        + NONCE_SIZE_BYTES
        + 2  # Fn_Len
        + len(fn_bytes)
        + 8  # Ciphertext_Len
    )
    crypto_overhead = SHA256_DIGEST_SIZE_BYTES + AES_GCM_TAG_SIZE_BYTES
    return header_overhead + crypto_overhead


def pack_payload(
    original_filename: str, ciphertext: bytes, salt: bytes, nonce: bytes
) -> bytes:
    """Pack encrypted payload and cryptographic metadata into a framed Crypta binary structure.

    Frame Specification (Version 2):
    [MAGIC (8B)] [VERSION (1B)] [SALT (16B)] [NONCE (12B)] [FN_LEN (2B)] [FILENAME] [CT_LEN (8B)] [CIPHERTEXT]
    """
    clean_name = Path(original_filename).name
    if not clean_name:
        clean_name = "payload.bin"

    fn_bytes = clean_name.encode("utf-8")
    fn_len = len(fn_bytes)
    if fn_len > 65535:
        raise ValueError("Filename exceeds maximum supported length (65535 bytes).")

    if len(salt) != SALT_SIZE_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes.")

    if len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE_BYTES} bytes.")

    ct_len = len(ciphertext)

    header = (
        MAGIC_BYTES
        + struct.pack("!B", HEADER_VERSION)
        + salt
        + nonce
        + struct.pack("!H", fn_len)
        + fn_bytes
        + struct.pack("!Q", ct_len)
    )
    return header + ciphertext


def unpack_payload(framed_bytes: bytes) -> Tuple[str, bytes, bytes, bytes]:
    """Unpack framed Crypta binary structure into (filename, ciphertext, salt, nonce).

    Raises:
        ValueError: If magic header missing, version unsupported, or payload corrupted.
    """
    magic_len = len(MAGIC_BYTES)
    # Minimum bytes required to check magic and version
    if len(framed_bytes) < magic_len + 1:
        raise ValueError("Crypta payload not found in carrier image.")

    # Validate Magic Header
    if not framed_bytes.startswith(MAGIC_BYTES):
        raise ValueError("Crypta payload not found in carrier image.")

    offset = magic_len

    # Unpack Version
    ver, = struct.unpack("!B", framed_bytes[offset : offset + 1])
    offset += 1

    if ver == HEADER_VERSION_LEGACY:
        raise ValueError(
            "Legacy unencrypted payload (Version 1) detected. "
            "Crypta Version 2 requires password-authenticated encrypted payloads."
        )

    if ver != HEADER_VERSION:
        raise ValueError(f"Unsupported Crypta payload version ({ver}).")

    # Minimum header size for Version 2:
    # Magic (8) + Ver (1) + Salt (16) + Nonce (12) + FnLen (2) + CtLen (8) = 47 bytes
    min_header_size = magic_len + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES + 2 + 8
    if len(framed_bytes) < min_header_size:
        raise ValueError("Corrupted or truncated Crypta payload header.")

    # Unpack Salt & Nonce
    salt = framed_bytes[offset : offset + SALT_SIZE_BYTES]
    offset += SALT_SIZE_BYTES

    nonce = framed_bytes[offset : offset + NONCE_SIZE_BYTES]
    offset += NONCE_SIZE_BYTES

    # Unpack Filename Length
    fn_len, = struct.unpack("!H", framed_bytes[offset : offset + 2])
    offset += 2

    if len(framed_bytes) < offset + fn_len + 8:
        raise ValueError("Corrupted or truncated Crypta payload header.")

    # Unpack Filename and Sanitize against Path Traversal
    fn_bytes = framed_bytes[offset : offset + fn_len]
    offset += fn_len
    raw_filename = fn_bytes.decode("utf-8", errors="replace")

    clean_filename = Path(raw_filename).name
    if not clean_filename or clean_filename in (".", ".."):
        clean_filename = "extracted_payload.bin"

    # Unpack Ciphertext Length
    ct_len, = struct.unpack("!Q", framed_bytes[offset : offset + 8])
    offset += 8

    if len(framed_bytes) < offset + ct_len:
        raise ValueError("Crypta payload is truncated or corrupted.")

    ciphertext = framed_bytes[offset : offset + ct_len]
    return clean_filename, ciphertext, salt, nonce
