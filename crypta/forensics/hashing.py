"""
SHA-256 Hashing & Fingerprinting Module for Crypta Forensics Engine.
Provides chunked, read-only SHA-256 calculation for arbitrary file paths.
"""

import hashlib
from pathlib import Path
from typing import Union


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Calculate the SHA-256 hexadecimal digest of a target file.

    Reads the file in binary chunks to handle arbitrarily large files memory-efficiently.
    Strictly read-only; never modifies the target file.

    Args:
        file_path: Path to target file.
        chunk_size: Read buffer chunk size in bytes (default 64 KB).

    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        FileNotFoundError: If file_path does not exist.
        ValueError: If file_path is a directory.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found for SHA-256 calculation: '{path}'")
    if not path.is_file():
        raise ValueError(f"Target path is not a file: '{path}'")

    hasher = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()
