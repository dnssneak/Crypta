"""
LSB Steganography Decoder for Crypta.
Wraps the core secure extract pipeline for extracting and decrypting hidden payloads from PNG images.
"""

from pathlib import Path
from typing import Optional, Tuple, Union
from crypta.core.pipeline import extract_file


def extract_payload(
    stego_path: Union[str, Path],
    password: str,
    output_destination: Optional[Union[str, Path]] = None,
) -> Tuple[Path, str, int]:
    """Extract a hidden payload from a Crypta stego PNG image, decrypt it, and write recovered file.

    Delegates to crypta.core.pipeline.extract_file.
    """
    res = extract_file(
        stego_path=stego_path,
        password=password,
        output_destination=output_destination,
        overwrite=True,
    )
    return res.output_path, res.restored_filename, res.recovered_size_bytes
