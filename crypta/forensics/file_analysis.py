"""
File-Level & Format Detection Analysis Module for Crypta Forensics Engine.
Extracts filesystem properties, SHA-256 fingerprint, and verifies extension vs detected image format.
"""

import time
from pathlib import Path
from typing import Union, Tuple
from PIL import Image, UnidentifiedImageError

from crypta.utils.validators import normalize_user_path, validate_file_exists
from crypta.steganography.capacity import format_size_bytes
from crypta.forensics.hashing import calculate_sha256
from crypta.forensics.results import FileProperties, FormatDetails


def inspect_file_properties(file_path: Union[str, Path]) -> Tuple[FileProperties, FormatDetails]:
    """Inspect filesystem properties, SHA-256 digest, and format consistency for a file.

    Args:
        file_path: Path to target file.

    Returns:
        Tuple[FileProperties, FormatDetails]: Basic file properties and detected format details.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If path is a directory.
    """
    path = validate_file_exists(file_path)
    stat = path.stat()

    file_size_bytes = stat.st_size
    size_human = format_size_bytes(file_size_bytes)

    # Format modification time clearly as filesystem metadata
    mod_time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(stat.st_mtime))
    sha256_hash = calculate_sha256(path)

    file_props = FileProperties(
        file_name=path.name,
        file_extension=path.suffix,
        file_path=path,
        size_bytes=file_size_bytes,
        size_human=size_human,
        exists=True,
        is_file=True,
        modified_time=mod_time_str,
        sha256_hash=sha256_hash,
    )

    # Detect actual format using Pillow header inspection
    ext_format = path.suffix.lstrip(".").upper()
    if not ext_format:
        ext_format = "NONE"

    try:
        with Image.open(path) as img:
            detected_format = img.format.upper() if img.format else "UNKNOWN"
    except (UnidentifiedImageError, OSError):
        detected_format = "UNKNOWN / NON-IMAGE"

    # Compare extension format vs detected image format
    # Map common extension aliases (e.g. JPG vs JPEG)
    norm_ext = "JPEG" if ext_format in ("JPG", "JPEG") else ext_format

    if detected_format == "UNKNOWN / NON-IMAGE":
        ext_match = False
        warning = f"File extension is '{path.suffix}', but file is not a valid recognized image."
    elif norm_ext == detected_format:
        ext_match = True
        warning = None
    else:
        ext_match = False
        warning = f"File extension '{path.suffix}' does not match actual detected format '{detected_format}'."

    fmt_details = FormatDetails(
        detected_format=detected_format,
        extension_format=ext_format,
        extension_match=ext_match,
        warning=warning,
    )

    return file_props, fmt_details
