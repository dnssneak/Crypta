"""
Validation utilities for files, paths, and carrier image types.
Uses pathlib for cross-platform compatibility.
"""

from pathlib import Path
from typing import Union
from crypta.utils.constants import SUPPORTED_IMAGE_FORMATS


def validate_file_exists(file_path: Union[str, Path]) -> Path:
    """Validate that a target file exists and is a file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: '{path}'")
    if not path.is_file():
        raise ValueError(f"Path is not a valid file: '{path}'")
    return path


def validate_image_format(image_path: Union[str, Path]) -> Path:
    """Validate that an image file exists and has a supported extension (PNG)."""
    path = validate_file_exists(image_path)
    if path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
        supported = ", ".join(SUPPORTED_IMAGE_FORMATS)
        raise ValueError(
            f"Unsupported image format '{path.suffix}'. Supported formats: {supported}"
        )
    return path


def ensure_output_directory(output_path: Union[str, Path]) -> Path:
    """Ensure the parent directory of an output file exists."""
    path = Path(output_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    return path
