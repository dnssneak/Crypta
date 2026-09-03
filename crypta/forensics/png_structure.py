"""
PNG Header & Structure Inspection Module for Crypta Forensics Engine.
Parses PNG 8-byte signature and IHDR chunk parameters directly from binary header.
"""

import struct
from pathlib import Path
from typing import Union, Optional
from crypta.forensics.results import PNGStructure

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

COLOR_TYPE_MAP = {
    0: "Grayscale",
    2: "Truecolor (RGB)",
    3: "Indexed-color (Palette)",
    4: "Grayscale with Alpha",
    6: "Truecolor with Alpha (RGBA)",
}

COMPRESSION_MAP = {
    0: "Deflate (32K window)",
}

FILTER_MAP = {
    0: "Adaptive filtering (5 basic types)",
}

INTERLACE_MAP = {
    0: "None (Standard raster)",
    1: "Adam7 interlacing",
}


def inspect_png_structure(file_path: Union[str, Path]) -> Optional[PNGStructure]:
    """Parse binary PNG signature and IHDR chunk metadata.

    Args:
        file_path: Path to target file.

    Returns:
        Optional[PNGStructure]: Parsed PNG structure if signature is valid, else None.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return None

    try:
        with path.open("rb") as f:
            header_bytes = f.read(33)
    except OSError:
        return None

    if len(header_bytes) < 33:
        return None

    signature = header_bytes[:8]
    if signature != PNG_SIGNATURE:
        return None

    # Parse IHDR chunk
    # Header format after 8B signature:
    # 4B chunk_length (must be 13), 4B chunk_type (b'IHDR'), 13B IHDR payload
    chunk_len, chunk_type = struct.unpack(">I4s", header_bytes[8:16])
    if chunk_type != b"IHDR" or chunk_len != 13:
        return PNGStructure(
            signature_valid=True,
            width=0,
            height=0,
            bit_depth=0,
            color_type_code=-1,
            color_type_desc="Invalid IHDR chunk",
            compression_method="Unknown",
            filter_method="Unknown",
            interlace_method="Unknown",
        )

    # Unpack 13-byte IHDR payload: Width(4B), Height(4B), BitDepth(1B), ColorType(1B), Compression(1B), Filter(1B), Interlace(1B)
    ihdr_data = header_bytes[16:29]
    width, height, bit_depth, color_type, comp_meth, filt_meth, inter_meth = struct.unpack(
        ">IIBBBBB", ihdr_data
    )

    color_desc = COLOR_TYPE_MAP.get(color_type, f"Custom / Unknown ({color_type})")
    comp_desc = COMPRESSION_MAP.get(comp_meth, f"Unknown ({comp_meth})")
    filt_desc = FILTER_MAP.get(filt_meth, f"Unknown ({filt_meth})")
    inter_desc = INTERLACE_MAP.get(inter_meth, f"Unknown ({inter_meth})")

    return PNGStructure(
        signature_valid=True,
        width=width,
        height=height,
        bit_depth=bit_depth,
        color_type_code=color_type,
        color_type_desc=color_desc,
        compression_method=comp_desc,
        filter_method=filt_desc,
        interlace_method=inter_desc,
    )
