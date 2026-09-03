"""
Crypta Forensics & Evidence Collection Package.
Provides read-only forensic inspection, SHA-256 fingerprinting, format detection, PNG header parsing, and metadata collection.
"""

from crypta.forensics.results import (
    FileProperties,
    FormatDetails,
    ImageProperties,
    PNGStructure,
    MetadataDetails,
    ForensicResult,
)
from crypta.forensics.hashing import calculate_sha256
from crypta.forensics.file_analysis import inspect_file_properties
from crypta.forensics.png_structure import inspect_png_structure
from crypta.forensics.metadata import extract_image_metadata, sanitize_metadata_text
from crypta.forensics.analyzer import analyze_forensics

__all__ = [
    "analyze_forensics",
    "calculate_sha256",
    "inspect_file_properties",
    "inspect_png_structure",
    "extract_image_metadata",
    "sanitize_metadata_text",
    "ForensicResult",
    "FileProperties",
    "FormatDetails",
    "ImageProperties",
    "PNGStructure",
    "MetadataDetails",
]
