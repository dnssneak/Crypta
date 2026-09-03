"""
Secure Hide and Extract Pipeline Orchestration Core for Crypta.
Integrates Carrier Validation, Argon2id Key Derivation, AES-256-GCM Encryption,
Crypta Binary Payload Framing, Capacity Analysis, LSB Embedding/Extraction,
SHA-256 Integrity Verification, and Transactional Atomic Output Writing.
"""

import os
import hashlib
import tempfile
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union
from PIL import Image

from crypta.utils.constants import (
    MAGIC_BYTES,
    HEADER_VERSION,
    HEADER_VERSION_LEGACY,
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)
from crypta.utils.validators import validate_file_exists, ensure_output_directory
from crypta.steganography.validators import validate_carrier_image
from crypta.steganography.capacity import check_payload_fit, format_size_bytes, calculate_usable_capacity_bytes
from crypta.steganography.payload import pack_payload, unpack_payload, calculate_framed_overhead
from crypta.steganography.lsb import bytes_to_bits, bits_to_bytes, embed_bits_in_image, extract_bits_from_image
from crypta.cryptography import encrypt_data, decrypt_data, AuthenticationError, DecryptionError, EncryptionError
from crypta.core.exceptions import CapacityError, CarrierValidationError, OutputCollisionError


@dataclass(frozen=True)
class HideResult:
    """Dataclass holding detailed metadata about a completed secure hide operation."""
    carrier_path: Path
    secret_path: Path
    output_path: Path
    original_size_bytes: int
    serialized_size_bytes: int
    sha256_hash: str


@dataclass(frozen=True)
class ExtractResult:
    """Dataclass holding detailed metadata about a completed secure extract operation."""
    stego_path: Path
    output_path: Path
    restored_filename: str
    recovered_size_bytes: int
    sha256_hash: str


def hide_file(
    carrier_path: Union[str, Path],
    secret_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
    overwrite: bool = False,
) -> HideResult:
    """Orchestrate secure hide pipeline: encrypt secret file and embed into PNG carrier image LSBs.

    Args:
        carrier_path: Path to carrier PNG image file.
        secret_path: Path to secret payload file to hide.
        output_path: Path for output stego PNG image.
        password: Plaintext password for Argon2id key derivation & AES-256-GCM encryption.
        overwrite: If True, overwrite existing output file.

    Returns:
        HideResult containing operation metadata.

    Raises:
        ValueError: If password empty or inputs invalid.
        CarrierValidationError: If carrier image invalid or unsupported.
        CapacityError: If carrier image capacity is insufficient for payload.
        OutputCollisionError: If output path exists and overwrite is False.
        EncryptionError: If payload encryption fails.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty.")

    # 1. Validate Carrier Image (Feature 2)
    try:
        carrier = validate_carrier_image(carrier_path)
    except Exception as err:
        raise CarrierValidationError(f"Invalid carrier image: {err}") from err

    # 2. Validate Secret File (Feature 2)
    secret_p = validate_file_exists(secret_path)
    if secret_p.is_dir():
        raise ValueError("Secret payload path cannot be a directory.")

    out_p = Path(output_path)
    if out_p.resolve() == carrier.path.resolve():
        raise ValueError("Output image path cannot be identical to the carrier image.")

    # 3. Check Output File Collision
    if out_p.exists() and not overwrite:
        raise OutputCollisionError(f"Output file already exists: {out_p.name}")

    ensure_output_directory(out_p)

    # 4. Read File & Calculate SHA-256 Digest
    raw_payload_bytes = secret_p.read_bytes()
    original_size = len(raw_payload_bytes)
    sha256_hash = hashlib.sha256(raw_payload_bytes).hexdigest()

    # 5. Perform AES-256-GCM Encryption + Argon2id Key Derivation (Feature 4)
    enc_result = encrypt_data(raw_payload_bytes, password)

    # 6. Build Version 2 Crypta Binary Payload (Feature 3/4)
    framed_payload = pack_payload(
        secret_p.name, enc_result.ciphertext, enc_result.salt, enc_result.nonce
    )
    serialized_size = len(framed_payload)

    # 7. Check Capacity Fit Against Usable Capacity
    usable_bytes = calculate_usable_capacity_bytes(carrier)
    if serialized_size > usable_bytes:
        req_str = format_size_bytes(serialized_size)
        avail_str = format_size_bytes(usable_bytes)
        raise CapacityError(
            f"Insufficient carrier capacity for '{secret_p.name}'.\n"
            f"  Required : {req_str} (Encrypted Payload + Crypta Framing)\n"
            f"  Available: {avail_str} Usable Capacity"
        )

    # 8. Perform Atomic LSB Embedding into Stego Image
    bits_to_embed = bytes_to_bits(framed_payload)

    # Create temporary file in destination directory for transactional safety
    temp_file = tempfile.NamedTemporaryFile(
        delete=False, dir=out_p.parent, prefix=".crypta_tmp_", suffix=".png"
    )
    temp_path = Path(temp_file.name)
    temp_file.close()

    try:
        with Image.open(carrier.path) as img:
            stego_img = embed_bits_in_image(img, bits_to_embed)
            stego_img.save(temp_path, format="PNG")

        # Atomic replacement / move to target output path
        os.replace(temp_path, out_p)
    except Exception as err:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise err

    return HideResult(
        carrier_path=carrier.path,
        secret_path=secret_p,
        output_path=out_p,
        original_size_bytes=original_size,
        serialized_size_bytes=serialized_size,
        sha256_hash=sha256_hash,
    )


def extract_file(
    stego_path: Union[str, Path],
    password: str,
    output_destination: Optional[Union[str, Path]] = None,
    overwrite: bool = False,
) -> ExtractResult:
    """Orchestrate secure extract pipeline: extract bitstream, parse payload, decrypt, and verify SHA-256 digest.

    Args:
        stego_path: Path to stego PNG image.
        password: Plaintext password for Argon2id key derivation & AES-256-GCM decryption.
        output_destination: Target output directory or file path for recovered payload.
        overwrite: If True, overwrite existing recovered output file.

    Returns:
        ExtractResult containing recovery metadata.

    Raises:
        ValueError: If password empty, payload missing, or header corrupted.
        CarrierValidationError: If stego image invalid or unreadable.
        AuthenticationError: If password incorrect or payload tampered.
        OutputCollisionError: If output file exists and overwrite is False.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty.")

    # 1. Validate Stego Carrier Image
    try:
        carrier = validate_carrier_image(stego_path)
    except Exception as err:
        raise CarrierValidationError(f"Invalid stego image: {err}") from err

    # 2. Extract Bitstream & Unpack Version 2 Binary Payload Frame
    with Image.open(carrier.path) as img:
        magic_len = len(MAGIC_BYTES)
        magic_bits_count = magic_len * 8
        first_bits = extract_bits_from_image(img, max_bits=magic_bits_count)
        first_bytes = bits_to_bytes(first_bits)

        if not first_bytes.startswith(MAGIC_BYTES):
            raise ValueError("Crypta payload not found in carrier image.")

        # Read Version byte
        ver_bits = extract_bits_from_image(img, max_bits=(magic_len + 1) * 8)
        ver_bytes = bits_to_bytes(ver_bits)
        ver, = struct.unpack("!B", ver_bytes[magic_len : magic_len + 1])

        if ver == HEADER_VERSION_LEGACY:
            raise ValueError(
                "Legacy unencrypted Crypta payload (Version 1) detected. "
                "Crypta Version 2 requires password-authenticated encrypted payloads."
            )

        if ver != HEADER_VERSION:
            raise ValueError(f"Unsupported Crypta payload version ({ver}).")

        # Read Version 2 header prefix length up to fn_len
        prefix_len = magic_len + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES + 2
        prefix_bits = extract_bits_from_image(img, max_bits=prefix_len * 8)
        prefix_bytes = bits_to_bytes(prefix_bits)

        fn_len_offset = magic_len + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES
        fn_len, = struct.unpack("!H", prefix_bytes[fn_len_offset : fn_len_offset + 2])

        header_prefix_len = prefix_len + fn_len + 8
        header_bits = extract_bits_from_image(img, max_bits=header_prefix_len * 8)
        header_bytes = bits_to_bytes(header_bits)

        ct_len_offset = prefix_len + fn_len
        ct_len, = struct.unpack("!Q", header_bytes[ct_len_offset : ct_len_offset + 8])

        total_frame_bytes = header_prefix_len + ct_len
        raw_capacity_bytes = carrier.width * carrier.height * carrier.channels // 8
        if total_frame_bytes > raw_capacity_bytes:
            raise ValueError("Corrupted or invalid Crypta payload length declared in header.")

        full_frame_bits = extract_bits_from_image(img, max_bits=total_frame_bytes * 8)
        full_frame_bytes = bits_to_bytes(full_frame_bits)

        restored_filename, ciphertext, salt, nonce = unpack_payload(full_frame_bytes)

    # 3. Perform AES-256-GCM Decryption + Argon2id Key Derivation & SHA-256 Verification
    recovered_bytes = decrypt_data(ciphertext, password, salt, nonce)
    sha256_hash = hashlib.sha256(recovered_bytes).hexdigest()

    # 4. Resolve Output Destination Path & Prevent Path Traversal
    safe_filename = Path(restored_filename).name
    if not safe_filename or safe_filename in (".", ".."):
        safe_filename = "extracted_payload.bin"

    if output_destination:
        dest_p = Path(output_destination)
        if dest_p.is_dir() or str(output_destination).endswith(("\\", "/")):
            final_out_path = dest_p / safe_filename
        else:
            final_out_path = dest_p
    else:
        final_out_path = Path.cwd() / safe_filename

    # 5. Output Collision Verification
    if final_out_path.exists() and not overwrite:
        raise OutputCollisionError(f"Output file already exists: {final_out_path.name}")

    ensure_output_directory(final_out_path)

    # 6. Perform Atomic File Writing for Recovered Secret File
    temp_file = tempfile.NamedTemporaryFile(
        delete=False, dir=final_out_path.parent, prefix=".crypta_rec_", suffix=".tmp"
    )
    temp_path = Path(temp_file.name)
    try:
        temp_file.write(recovered_bytes)
        temp_file.close()

        # Atomic move / replace
        os.replace(temp_path, final_out_path)
    except Exception as err:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise err

    return ExtractResult(
        stego_path=carrier.path,
        output_path=final_out_path,
        restored_filename=safe_filename,
        recovered_size_bytes=len(recovered_bytes),
        sha256_hash=sha256_hash,
    )
