"""
LSB Steganography Encoder for Crypta.
Encrypts payloads with AES-256-GCM + Argon2id and embeds framed bitstreams into PNG carrier images.
"""

from pathlib import Path
from typing import Union
from PIL import Image

from crypta.utils.validators import validate_file_exists, ensure_output_directory
from crypta.steganography.validators import validate_carrier_image
from crypta.steganography.capacity import check_payload_fit, format_size_bytes
from crypta.steganography.payload import pack_payload, calculate_framed_overhead
from crypta.steganography.lsb import bytes_to_bits, embed_bits_in_image
from crypta.cryptography import encrypt_data


def embed_payload(
    carrier_path: Union[str, Path],
    secret_file_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
) -> Path:
    """Encrypt and embed a secret file into a carrier PNG image and save as a new PNG stego image.

    Raises:
        FileNotFoundError: If carrier or secret file does not exist.
        ValueError: If carrier is invalid, capacity is insufficient, or inputs invalid.
        EncryptionError: If payload encryption fails.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    carrier = validate_carrier_image(carrier_path)
    secret_path = validate_file_exists(secret_file_path)

    raw_payload_data = secret_path.read_bytes()

    # 1. Perform AES-256-GCM encryption + Argon2id key derivation
    enc_res = encrypt_data(raw_payload_data, password)

    # 2. Pack encrypted payload and metadata into Crypta Version 2 frame
    framed_payload = pack_payload(
        secret_path.name, enc_res.ciphertext, enc_res.salt, enc_res.nonce
    )
    overhead = calculate_framed_overhead(secret_path.name)

    # 3. Check carrier capacity based on actual encrypted framed payload size
    fits, required_bytes, usable_bytes = check_payload_fit(
        carrier, len(raw_payload_data), overhead_bytes=overhead
    )

    if not fits:
        req_str = format_size_bytes(required_bytes)
        avail_str = format_size_bytes(usable_bytes)
        raise ValueError(
            f"Insufficient carrier capacity for '{secret_path.name}'.\n"
            f"Required : {req_str} (Encrypted Payload + Crypta Framing)\n"
            f"Available: {avail_str} Usable Capacity"
        )

    # 4. Embed bitstream into PNG image LSBs
    bits_to_embed = bytes_to_bits(framed_payload)

    with Image.open(carrier.path) as img:
        stego_img = embed_bits_in_image(img, bits_to_embed)

        out_path = ensure_output_directory(output_path)
        stego_img.save(out_path, format="PNG")
        return out_path
