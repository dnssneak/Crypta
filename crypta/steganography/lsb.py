"""
Low-level LSB bit manipulation and spatial-domain image pixel embedding engine.
Enforces deterministic MSB-first bit ordering and preserves RGBA alpha channels.
"""

from typing import List, Optional
from PIL import Image


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of bits using MSB-first ordering."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bits to bytes using MSB-first ordering.

    Truncates incomplete trailing bits that do not form a full 8-bit byte.
    """
    num_bytes = len(bits) // 8
    byte_list = bytearray(num_bytes)
    for i in range(num_bytes):
        byte_val = 0
        bit_offset = i * 8
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | bits[bit_offset + bit_idx]
        byte_list[i] = byte_val
    return bytes(byte_list)


def embed_bits_in_image(img: Image.Image, bits: List[int]) -> Image.Image:
    """Embed a bitstream into the LSBs of usable image color channels (R, G, B).

    For RGBA images, the Alpha (A) channel is preserved without modification.
    Returns a new Image instance without mutating the original.
    """
    if img.mode not in ("RGB", "RGBA"):
        raise ValueError(f"Unsupported image mode '{img.mode}'. Expected RGB or RGBA.")

    stego_img = img.copy()
    pixels = list(stego_img.getdata())
    num_bits = len(bits)
    is_rgba = img.mode == "RGBA"

    total_capacity_bits = len(pixels) * 3
    if num_bits > total_capacity_bits:
        raise ValueError(
            f"Payload bitstream ({num_bits} bits) exceeds available image capacity ({total_capacity_bits} bits)."
        )

    new_pixels = []
    bit_idx = 0

    for px in pixels:
        if bit_idx >= num_bits:
            new_pixels.append(px)
            continue

        r = px[0]
        g = px[1]
        b = px[2]

        # Embed in Red channel
        if bit_idx < num_bits:
            r = (r & ~1) | bits[bit_idx]
            bit_idx += 1

        # Embed in Green channel
        if bit_idx < num_bits:
            g = (g & ~1) | bits[bit_idx]
            bit_idx += 1

        # Embed in Blue channel
        if bit_idx < num_bits:
            b = (b & ~1) | bits[bit_idx]
            bit_idx += 1

        if is_rgba:
            a = px[3]  # Alpha channel remains untouched
            new_pixels.append((r, g, b, a))
        else:
            new_pixels.append((r, g, b))

    stego_img.putdata(new_pixels)
    return stego_img


def extract_bits_from_image(img: Image.Image, max_bits: Optional[int] = None) -> List[int]:
    """Extract LSB bits from usable color channels (R, G, B) of an image.

    Ignores Alpha channel if present.
    If max_bits is specified, extraction stops after reading max_bits.
    """
    if img.mode not in ("RGB", "RGBA"):
        raise ValueError(f"Unsupported image mode '{img.mode}'. Expected RGB or RGBA.")

    pixels = img.getdata()
    extracted_bits = []

    for px in pixels:
        # Extract Red LSB
        extracted_bits.append(px[0] & 1)
        if max_bits and len(extracted_bits) >= max_bits:
            break

        # Extract Green LSB
        extracted_bits.append(px[1] & 1)
        if max_bits and len(extracted_bits) >= max_bits:
            break

        # Extract Blue LSB
        extracted_bits.append(px[2] & 1)
        if max_bits and len(extracted_bits) >= max_bits:
            break

    return extracted_bits
