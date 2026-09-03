"""
Crypta Core Package.
Provides orchestration pipeline APIs for secure steganographic hide and extract operations.
"""

from crypta.core.exceptions import (
    PipelineError,
    CapacityError,
    CarrierValidationError,
    OutputCollisionError,
)
from crypta.core.pipeline import hide_file, extract_file, HideResult, ExtractResult

__all__ = [
    "PipelineError",
    "CapacityError",
    "CarrierValidationError",
    "OutputCollisionError",
    "hide_file",
    "extract_file",
    "HideResult",
    "ExtractResult",
]
