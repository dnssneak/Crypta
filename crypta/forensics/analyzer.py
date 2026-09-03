"""
High-Level Forensic Orchestration Service for Crypta.
Coordinates file property inspection, format detection, PNG header analysis, and metadata extraction.
Strictly read-only; guarantees original file immutability.
"""

from pathlib import Path
from typing import Union, List

from crypta.utils.validators import validate_file_exists
from crypta.forensics.results import ForensicResult
from crypta.forensics.file_analysis import inspect_file_properties
from crypta.forensics.png_structure import inspect_png_structure
from crypta.forensics.metadata import extract_image_metadata


def analyze_forensics(image_path: Union[str, Path]) -> ForensicResult:
    """Perform comprehensive read-only forensic analysis on a target image file.

    Args:
        image_path: Path to target file.

    Returns:
        ForensicResult: Structured forensic evidence result object.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If file path is a directory or invalid.
    """
    path = validate_file_exists(image_path)

    # 1. File Properties, SHA-256 Hashing, & Format Detection
    file_props, fmt_details = inspect_file_properties(path)

    # 2. PNG Binary Header Structure Inspection
    png_struct = inspect_png_structure(path)

    # 3. Image Properties & Embedded Metadata Extraction
    warnings: List[str] = []
    if fmt_details.warning:
        warnings.append(fmt_details.warning)

    try:
        img_props, meta_details = extract_image_metadata(path)
    except Exception as err:
        warnings.append(f"Unable to parse image properties/metadata: {err}")
        # Build fallback image properties from file info if Pillow fails
        from crypta.forensics.results import ImageProperties, MetadataDetails
        img_props = ImageProperties(
            width=png_struct.width if png_struct else 0,
            height=png_struct.height if png_struct else 0,
            mode="UNKNOWN",
            channels=0,
        )
        meta_details = MetadataDetails(
            exif_present=False,
            exif_tags={},
            text_metadata={},
            text_entry_count=0,
            summary="Metadata extraction unreadable",
        )

    return ForensicResult(
        file=file_props,
        format=fmt_details,
        image=img_props,
        png_structure=png_struct,
        metadata=meta_details,
        warnings=warnings,
    )
