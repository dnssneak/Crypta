"""
Crypta Core Pipeline Exceptions Module.
Defines domain exceptions for workflow orchestration, capacity errors, and file collisions.
"""

from crypta.cryptography.exceptions import CryptaError


class PipelineError(CryptaError):
    """Base exception for pipeline orchestration errors."""
    pass


class CapacityError(PipelineError, ValueError):
    """Raised when secret payload exceeds carrier image usable capacity."""
    pass


class CarrierValidationError(PipelineError, ValueError):
    """Raised when carrier image validation fails."""
    pass


class OutputCollisionError(PipelineError, FileExistsError):
    """Raised when the designated output file already exists and overwrite is False."""
    pass
