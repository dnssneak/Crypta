"""
Structured Forensic Result objects for Crypta Forensics & Evidence Collection Engine.
Provides strongly-typed dataclasses for storing forensic evidence and JSON-serializable export.
"""

from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Any


@dataclass
class FileProperties:
    """Basic file system metadata and fingerprint."""

    file_name: str
    file_extension: str
    file_path: Path
    size_bytes: int
    size_human: str
    exists: bool
    is_file: bool
    modified_time: str
    sha256_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        d = asdict(self)
        d["file_path"] = str(self.file_path)
        return d


@dataclass
class FormatDetails:
    """Image format detection and extension consistency details."""

    detected_format: str
    extension_format: str
    extension_match: bool
    warning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class ImageProperties:
    """Pillow image properties and color channel details."""

    width: int
    height: int
    mode: str
    channels: int
    bits_per_channel: Optional[int] = 8

    @property
    def dimensions_str(self) -> str:
        """Formatted dimensions string W x H."""
        return f"{self.width} × {self.height}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        d = asdict(self)
        d["dimensions_str"] = self.dimensions_str
        return d


@dataclass
class PNGStructure:
    """PNG binary structure and IHDR chunk metadata."""

    signature_valid: bool
    width: int
    height: int
    bit_depth: int
    color_type_code: int
    color_type_desc: str
    compression_method: str
    filter_method: str
    interlace_method: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class MetadataDetails:
    """Embedded metadata, EXIF, and PNG textual metadata findings."""

    exif_present: bool
    exif_tags: Dict[str, str]
    text_metadata: Dict[str, str]
    text_entry_count: int
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class ForensicResult:
    """Master container aggregating all forensic analysis findings for a file."""

    file: FileProperties
    format: FormatDetails
    image: ImageProperties
    png_structure: Optional[PNGStructure]
    metadata: MetadataDetails
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert full forensic result into a JSON-serializable dictionary."""
        return {
            "file": self.file.to_dict(),
            "format": self.format.to_dict(),
            "image": self.image.to_dict(),
            "png_structure": self.png_structure.to_dict() if self.png_structure else None,
            "metadata": self.metadata.to_dict(),
            "warnings": self.warnings,
        }
