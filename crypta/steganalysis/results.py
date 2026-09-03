"""
Structured analysis result objects for Crypta Steganalysis Engine.
Provides strongly-typed dataclasses for storing statistical metrics and JSON-serializable export.
"""

from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Any


@dataclass
class ImageInfo:
    """Basic image metadata and channel specification for steganalysis."""

    file_path: Path
    file_name: str
    format: str
    width: int
    height: int
    mode: str
    channels: int
    file_size_bytes: int
    analyzed_channels: List[str]
    alpha_excluded: bool

    @property
    def dimensions_str(self) -> str:
        """Formatted dimensions string W x H."""
        return f"{self.width} × {self.height}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        d = asdict(self)
        d["file_path"] = str(self.file_path)
        return d


@dataclass
class EntropyResult:
    """Shannon entropy analysis results."""

    overall_entropy: float
    per_channel_entropy: Dict[str, float]
    observation: str
    channel_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class LSBResult:
    """Least Significant Bit (LSB) distribution analysis results."""

    zero_counts: Dict[str, int]
    one_counts: Dict[str, int]
    zero_percentages: Dict[str, float]
    one_percentages: Dict[str, float]
    deviations: Dict[str, float]
    observation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class ChiSquareResult:
    """Chi-Square statistical analysis results for LSB replacement testing."""

    statistics: Dict[str, float]
    degrees_of_freedom: Dict[str, int]
    p_values: Dict[str, Optional[float]]
    observation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class HistogramResult:
    """Histogram and intensity distribution analysis results."""

    channel_stats: Dict[str, Dict[str, float]]
    adjacent_pair_ratios: Dict[str, float]
    observation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class PixelStatsResult:
    """Basic pixel and spatial statistical analysis results."""

    total_pixels: int
    channel_means: Dict[str, float]
    channel_stds: Dict[str, float]
    channel_mins: Dict[str, int]
    channel_maxs: Dict[str, int]
    unique_values: Dict[str, int]
    lsb_transition_frequencies: Dict[str, float]
    observation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to serializable dictionary."""
        return asdict(self)


@dataclass
class AnalysisResult:
    """Master container aggregating all steganalysis results for an image."""

    image_info: ImageInfo
    entropy: EntropyResult
    lsb_analysis: LSBResult
    chi_square: ChiSquareResult
    histogram: HistogramResult
    pixel_statistics: PixelStatsResult
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert full analysis result into a JSON-serializable dictionary."""
        return {
            "image_info": self.image_info.to_dict(),
            "entropy": self.entropy.to_dict(),
            "lsb_analysis": self.lsb_analysis.to_dict(),
            "chi_square": self.chi_square.to_dict(),
            "histogram": self.histogram.to_dict(),
            "pixel_statistics": self.pixel_statistics.to_dict(),
            "observations": self.observations,
        }
