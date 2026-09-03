"""
LSB Steganography Decoder for Crypta.
Detects Crypta magic headers, extracts framed payload bitstreams, and decrypts recovered payloads.
"""

import struct
from pathlib import Path
from typing import Optional, Tuple, Union
from PIL import Image

from crypta.utils.constants import (
    MAGIC_BYTES,
    HEADER_VERSION,
    HEADER_VERSION_LEGACY,
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)
from crypta.utils.validators import ensure_output_directory
from crypta.steganography.validators import validate_carrier_image
from crypta.steganography.payload import unpack_payload
from crypta.steganography.lsb import extract_bits_from_image, bits_to_bytes
from crypta.cryptography import decrypt_data, CryptaError


def extract_payload(
    stego_path: Union[str, Path],
    password: str,
    output_destination: Optional[Union[str, Path]] = None,
) -> Tuple[Path, str, int]:
    """Extract a hidden payload from a Crypta stego PNG image, decrypt it, and write recovered file.

    Returns:
        Tuple containing:
        - output_file_path (Path): Path to the written recovered file
        - original_filename (str): Restored original filename
        - payload_size_bytes (int): Size of recovered file in bytes

    Raises:
        FileNotFoundError: If stego image file does not exist.
        ValueError: If Crypta payload missing, magic corrupted, version unsupported, or inputs invalid.
        AuthenticationError: If decryption/authentication fails.
        DecryptionError: If decryption fails.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    carrier = validate_carrier_image(stego_path)

    with Image.open(carrier.path) as img:
        magic_len = len(MAGIC_BYTES)
        magic_bits_count = magic_len * 8
        first_bits = extract_bits_from_image(img, max_bits=magic_bits_count)
        first_bytes = bits_to_bytes(first_bits)

        if not first_bytes.startswith(MAGIC_BYTES):
            raise ValueError("Crypta payload not found in carrier image.")

        # Read Version byte at offset magic_len (1B)
        ver_bits = extract_bits_from_image(img, max_bits=(magic_len + 1) * 8)
        ver_bytes = bits_to_bytes(ver_bits)
        ver, = struct.unpack("!B", ver_bytes[magic_len : magic_len + 1])

        if ver == HEADER_VERSION_LEGACY:
            raise ValueError(
                "Legacy unencrypted payload (Version 1) detected. "
                "Crypta Version 2 requires password-authenticated encrypted payloads."
            )

        if ver != HEADER_VERSION:
            raise ValueError(f"Unsupported Crypta payload version ({ver}).")

        # Fixed Version 2 header prefix length up to fn_len:
        # Magic (8) + Ver (1) + Salt (16) + Nonce (12) + FnLen (2) = 39 bytes
        prefix_len = magic_len + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES + 2
        prefix_bits = extract_bits_from_image(img, max_bits=prefix_len * 8)
        prefix_bytes = bits_to_bytes(prefix_bits)

        fn_len_offset = magic_len + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES
        fn_len, = struct.unpack("!H", prefix_bytes[fn_len_offset : fn_len_offset + 2])

        # Calculate exact total header bytes up to ct_len:
        # prefix_len (39) + fn_len + CtLen (8) = 47 + fn_len
        header_prefix_len = prefix_len + fn_len + 8
        header_bits = extract_bits_from_image(img, max_bits=header_prefix_len * 8)
        header_bytes = bits_to_bytes(header_bits)

        ct_len_offset = prefix_len + fn_len
        ct_len, = struct.unpack(
            "!Q", header_bytes[ct_len_offset : ct_len_offset + 8]
        )

        total_frame_bytes = header_prefix_len + ct_len
        total_frame_bits = total_frame_bytes * 8

        raw_capacity_bytes = carrier.width * carrier.height * carrier.channels // 8
        if total_frame_bytes > raw_capacity_bytes:
            raise ValueError("Corrupted or invalid Crypta payload length declared in header.")

        full_frame_bits = extract_bits_from_image(img, max_bits=total_frame_bits)
        full_frame_bytes = bits_to_bytes(full_frame_bits)

        # Unpack Version 2 frame
        restored_filename, ciphertext, salt, nonce = unpack_payload(full_frame_bytes)

        # Decrypt ciphertext using derived key
        plaintext = decrypt_data(ciphertext, password, salt, nonce)

        # Resolve output destination path safely
        if output_destination:
            dest_p = Path(output_destination)
            if dest_p.is_dir() or str(output_destination).endswith(("\\", "/")):
                final_out_path = dest_p / restored_filename
            else:
                final_out_path = dest_p
        else:
            final_out_path = Path.cwd() / restored_filename

        final_out_path = ensure_output_directory(final_out_path)
        final_out_path.write_bytes(plaintext)

        return final_out_path, restored_filename, len(plaintext)
