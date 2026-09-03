"""
LSB Steganography Encoder for Crypta.
Wraps the core secure hide pipeline for embedding framed bitstreams into PNG carrier images.
"""

from pathlib import Path
from typing import Union
from crypta.core.pipeline import hide_file


def embed_payload(
    carrier_path: Union[str, Path],
    secret_file_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
) -> Path:
    """Encrypt and embed a secret file into a carrier PNG image and save as a new PNG stego image.

    Delegates to crypta.core.pipeline.hide_file.
    """
    res = hide_file(
        carrier_path=carrier_path,
        secret_path=secret_file_path,
        output_path=output_path,
        password=password,
        overwrite=True,
    )
    return res.output_path
