"""
Crypta Cryptography Package.
Provides Argon2id key derivation, AES-256-GCM encryption/decryption, and cryptographic exceptions.
"""

from crypta.cryptography.exceptions import (
    CryptaError,
    EncryptionError,
    DecryptionError,
    AuthenticationError,
    InvalidPayloadError,
)
from crypta.cryptography.key_derivation import derive_key
from crypta.cryptography.encryption import EncryptionResult, encrypt_data
from crypta.cryptography.decryption import decrypt_data

__all__ = [
    "CryptaError",
    "EncryptionError",
    "DecryptionError",
    "AuthenticationError",
    "InvalidPayloadError",
    "derive_key",
    "EncryptionResult",
    "encrypt_data",
    "decrypt_data",
]
