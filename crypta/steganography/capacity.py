"""
Mathematical carrier capacity calculation engine for Crypta.
Determines raw LSB capacity, reserves payload overhead, and verifies payload fit.
"""

from pathlib import Path
from typing import Tuple, Union
from crypta.steganography.carrier import CarrierImage
from crypta.utils.validators import validate_file_exists

# Default reserved space in bytes for Crypta magic header, version, salt, nonce, filename & SHA-256 digest
DEFAULT_PAYLOAD_OVERHEAD_BYTES = 256


def calculate_raw_capacity_bits(carrier: CarrierImage) -> int:
    """Calculate raw available LSB capacity in bits (1 LSB bit per color channel)."""
    return carrier.width * carrier.height * carrier.channels


def calculate_raw_capacity_bytes(carrier: CarrierImage) -> int:
    """Calculate raw available LSB capacity in bytes."""
    return calculate_raw_capacity_bits(carrier) // 8


def calculate_usable_capacity_bytes(
    carrier: CarrierImage, overhead_bytes: int = DEFAULT_PAYLOAD_OVERHEAD_BYTES
) -> int:
    """Calculate net usable payload capacity after reserving overhead bytes."""
    raw_bytes = calculate_raw_capacity_bytes(carrier)
    return max(0, raw_bytes - overhead_bytes)


def get_payload_size(payload_path: Union[str, Path]) -> int:
    """Get payload file size in bytes without loading contents into memory."""
    path = validate_file_exists(payload_path)
    return path.stat().st_size


def check_payload_fit(
    carrier: CarrierImage,
    payload_size_bytes: int,
    overhead_bytes: int = DEFAULT_PAYLOAD_OVERHEAD_BYTES,
) -> Tuple[bool, int, int]:
    """Determine whether a payload file size fits inside the carrier image.

    Returns:
        Tuple containing:
        - fits (bool): True if total required size <= raw capacity
        - total_required_bytes (int): payload size + reserved overhead bytes
        - usable_available_bytes (int): net usable carrier payload capacity
    """
    total_required = payload_size_bytes + overhead_bytes
    usable_available = calculate_usable_capacity_bytes(carrier, overhead_bytes)
    fits = payload_size_bytes <= usable_available
    return fits, total_required, usable_available


def format_size_bytes(num_bytes: int) -> str:
    """Format byte counts into human-readable strings (Bytes, KiB, MiB)."""
    if num_bytes < 1024:
        return f"{num_bytes} Bytes"
    elif num_bytes < 1024 * 1024:
        kib = num_bytes / 1024.0
        return f"{kib:.2f} KiB ({num_bytes:,} Bytes)"
    else:
        mib = num_bytes / (1024.0 * 1024.0)
        return f"{mib:.2f} MiB ({num_bytes:,} Bytes)"
