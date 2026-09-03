"""
Carrier image validation engine for Crypta.
Handles file inspection, Pillow integrity verification, format, and color channel validation.
"""

from pathlib import Path
from typing import Union
from PIL import Image, UnidentifiedImageError

from crypta.utils.validators import validate_file_exists
from crypta.steganography.carrier import CarrierImage

# MVP Supported Modes & Channel Mapping
SUPPORTED_MODES = {
    "RGB": 3,
    "RGBA": 4,
}


def validate_carrier_image(image_path: Union[str, Path]) -> CarrierImage:
    """Validate a carrier image path and return a CarrierImage abstraction.

    Raises:
        FileNotFoundError: If the carrier file does not exist.
        ValueError: If the file is not a valid, supported PNG image or has corrupted data.
    """
    path = validate_file_exists(image_path)

    # Attempt Pillow open and format validation
    try:
        with Image.open(path) as img:
            detected_format = img.format
            # Format check (Pillow detects format independently of file extension)
            if not detected_format or detected_format.upper() != "PNG":
                fmt_display = detected_format.upper() if detected_format else "Unknown"
                raise ValueError(
                    f"Unsupported carrier format: {fmt_display}. Crypta currently supports PNG carriers only."
                )

            # Integrity verification
            try:
                img.verify()
            except Exception as err:
                raise ValueError(f"Unable to validate carrier image. The image may be corrupted or invalid: {err}")
    except (UnidentifiedImageError, OSError) as err:
        if isinstance(err, ValueError):
            raise
        raise ValueError(f"Invalid or corrupted image file '{path.name}'. Unable to open.")

    # Re-open after verify() to inspect mode and dimensions
    with Image.open(path) as img:
        mode = img.mode
        if mode not in SUPPORTED_MODES:
            supported_str = ", ".join(SUPPORTED_MODES.keys())
            raise ValueError(
                f"Unsupported image color mode '{mode}'. Crypta supports PNG carriers with modes: {supported_str}."
            )

        channels = SUPPORTED_MODES[mode]
        width, height = img.size
        file_size_bytes = path.stat().st_size

        return CarrierImage(
            path=path,
            format="PNG",
            width=width,
            height=height,
            mode=mode,
            channels=channels,
            file_size_bytes=file_size_bytes,
        )
