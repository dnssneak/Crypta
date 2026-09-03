"""
Metadata & Image Property Extraction Module for Crypta Forensics Engine.
Extracts Pillow image properties, PNG text metadata (tEXt/zTXt/iTXt), and EXIF tags with terminal safety sanitization.
"""

import re
from pathlib import Path
from typing import Union, Tuple, Dict, Any, Optional
from PIL import Image, ExifTags

from crypta.forensics.results import ImageProperties, MetadataDetails

# Color mode to channel count mapping
MODE_CHANNELS = {
    "1": 1,
    "L": 1,
    "P": 1,
    "RGB": 3,
    "RGBA": 4,
    "CMYK": 4,
    "YCbCr": 3,
    "LAB": 3,
    "HSV": 3,
    "I": 1,
    "F": 1,
}


def sanitize_metadata_text(text: str) -> str:
    """Sanitize text extracted from image metadata.

    Strips terminal escape sequences and non-printable control characters to prevent terminal injection.

    Args:
        text: Raw metadata text.

    Returns:
        str: Sanitized, safe text string.
    """
    if not isinstance(text, str):
        text = str(text)
    # Remove ANSI control sequences and non-printable control codes (except space and newline)
    sanitized = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)
    return sanitized.strip()


def extract_image_metadata(file_path: Union[str, Path]) -> Tuple[ImageProperties, MetadataDetails]:
    """Extract Pillow image properties and embedded metadata (EXIF + PNG text chunks).

    Args:
        file_path: Path to target image file.

    Returns:
        Tuple[ImageProperties, MetadataDetails]: Extracted image properties and metadata findings.
    """
    path = Path(file_path)

    with Image.open(path) as img:
        width, height = img.size
        mode = img.mode
        channels = MODE_CHANNELS.get(mode, len(img.getbands()) if hasattr(img, "getbands") else 3)

        img_props = ImageProperties(
            width=width,
            height=height,
            mode=mode,
            channels=channels,
            bits_per_channel=8,
        )

        # 1. Extract PNG Text Metadata (tEXt, zTXt, iTXt stored in img.info)
        text_metadata: Dict[str, str] = {}
        raw_info = getattr(img, "info", {})

        for key, val in raw_info.items():
            # Skip non-textual internal Pillow objects
            if isinstance(val, (str, int, float)):
                clean_key = sanitize_metadata_text(str(key))
                clean_val = sanitize_metadata_text(str(val))
                if clean_key and clean_val:
                    text_metadata[clean_key] = clean_val
            elif isinstance(val, bytes):
                try:
                    clean_key = sanitize_metadata_text(str(key))
                    clean_val = sanitize_metadata_text(val.decode("utf-8", errors="replace"))
                    if clean_key and clean_val:
                        text_metadata[clean_key] = clean_val
                except Exception:
                    pass

        # 2. Extract EXIF Tags if present
        exif_tags: Dict[str, str] = {}
        exif_present = False

        try:
            exif_data = img.getexif()
            if exif_data and len(exif_data) > 0:
                exif_present = True
                for tag_id, val in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                    clean_val = sanitize_metadata_text(str(val))
                    exif_tags[tag_name] = clean_val
        except Exception:
            exif_present = False

        text_count = len(text_metadata)

        # Build human-readable metadata summary
        summaries = []
        if exif_present:
            summaries.append(f"EXIF Present ({len(exif_tags)} tags)")
        else:
            summaries.append("EXIF Not Present")

        if text_count > 0:
            summaries.append(f"Text Metadata ({text_count} entries)")
        else:
            summaries.append("No Text Metadata")

        summary_str = " | ".join(summaries)

        meta_details = MetadataDetails(
            exif_present=exif_present,
            exif_tags=exif_tags,
            text_metadata=text_metadata,
            text_entry_count=text_count,
            summary=summary_str,
        )

        return img_props, meta_details
