"""
Carrier image data abstraction for Crypta.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class CarrierImage:
    """Represents a validated carrier image with structural metadata."""

    path: Path
    format: str
    width: int
    height: int
    mode: str
    channels: int
    file_size_bytes: int

    @property
    def dimensions_str(self) -> str:
        """Return dimensions formatted as W x H."""
        return f"{self.width} × {self.height}"

    @property
    def total_pixels(self) -> int:
        """Return total pixel count."""
        return self.width * self.height
