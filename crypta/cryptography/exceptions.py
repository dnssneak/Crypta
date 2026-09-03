"""
Crypta Cryptography Exceptions Module.
Defines domain exceptions for encryption, decryption, authentication, and payload parsing failures.
"""


class CryptaError(Exception):
    """Base exception for all Crypta application errors."""
    pass


class EncryptionError(CryptaError):
    """Raised when an encryption operation fails."""
    pass


class DecryptionError(CryptaError):
    """Raised when a decryption operation fails."""
    pass


class AuthenticationError(DecryptionError):
    """Raised when AES-GCM authentication or SHA-256 integrity verification fails."""
    pass


class InvalidPayloadError(CryptaError):
    """Raised when encountering malformed, corrupted, or unsupported payload structures."""
    pass
