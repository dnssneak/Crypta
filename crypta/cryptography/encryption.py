"""
AES-256-GCM Encryption Module for Crypta.
Handles secure key derivation, nonce generation, SHA-256 integrity tagging, and AES-GCM encryption.
"""

import hashlib
import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypta.utils.constants import SALT_SIZE_BYTES, NONCE_SIZE_BYTES
from crypta.cryptography.key_derivation import derive_key
from crypta.cryptography.exceptions import EncryptionError


@dataclass(frozen=True)
class EncryptionResult:
    """Container holding encrypted ciphertext along with non-secret salt and nonce metadata."""
    ciphertext: bytes
    salt: bytes
    nonce: bytes


def encrypt_data(plaintext: bytes, password: str) -> EncryptionResult:
    """Encrypt plaintext binary payload using AES-256-GCM with Argon2id derived key.

    Integrates SHA-256 digest of original plaintext inside the authenticated ciphertext payload.

    Args:
        plaintext: Raw input bytes to encrypt.
        password: User password for key derivation.

    Returns:
        EncryptionResult containing ciphertext, salt, and nonce.

    Raises:
        ValueError: If plaintext is not bytes or password is invalid.
        EncryptionError: If key derivation or encryption fails.
    """
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext payload must be bytes.")

    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    # 1. Compute SHA-256 digest of original plaintext for post-decryption integrity verification
    digest = hashlib.sha256(plaintext).digest()
    inner_payload = digest + plaintext

    # 2. Generate unique random salt and derive key
    salt = secrets.token_bytes(SALT_SIZE_BYTES)
    key = derive_key(password, salt)

    # 3. Generate unique random nonce for AES-GCM
    nonce = secrets.token_bytes(NONCE_SIZE_BYTES)

    # 4. Perform AES-256-GCM authenticated encryption
    try:
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, inner_payload, associated_data=None)
        return EncryptionResult(ciphertext=ciphertext, salt=salt, nonce=nonce)
    except Exception as err:
        raise EncryptionError(f"AES-256-GCM encryption failed: {err}") from err
