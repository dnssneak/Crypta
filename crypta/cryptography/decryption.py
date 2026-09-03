"""
AES-256-GCM Decryption Module for Crypta.
Handles key re-derivation, AES-GCM authentication verification, and SHA-256 plaintext integrity validation.
"""

import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from crypta.utils.constants import (
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    SHA256_DIGEST_SIZE_BYTES,
)
from crypta.cryptography.key_derivation import derive_key
from crypta.cryptography.exceptions import DecryptionError, AuthenticationError


def decrypt_data(
    ciphertext: bytes, password: str, salt: bytes, nonce: bytes
) -> bytes:
    """Decrypt AES-256-GCM authenticated ciphertext using Argon2id derived key.

    Verifies both AES-GCM authentication tag and embedded SHA-256 digest.

    Args:
        ciphertext: Encrypted payload bytes (including AES-GCM tag).
        password: User password for key derivation.
        salt: 16-byte random salt stored in payload.
        nonce: 12-byte random nonce stored in payload.

    Returns:
        Recovered original plaintext payload bytes.

    Raises:
        ValueError: If input parameter types or lengths are invalid.
        AuthenticationError: If authentication tag check or SHA-256 digest check fails.
        DecryptionError: If decryption fails due to corrupted data.
    """
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes.")

    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes long.")

    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE_BYTES} bytes long.")

    # 1. Re-derive key using salt and password
    key = derive_key(password, salt)

    # 2. Decrypt ciphertext using AES-256-GCM
    try:
        aesgcm = AESGCM(key)
        inner_payload = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as err:
        raise AuthenticationError(
            "Decryption failed: invalid password or corrupted payload."
        ) from err
    except Exception as err:
        raise DecryptionError(
            "Decryption failed: invalid password or corrupted payload."
        ) from err

    # 3. Unpack SHA-256 digest and plaintext
    if len(inner_payload) < SHA256_DIGEST_SIZE_BYTES:
        raise DecryptionError("Decrypted payload is truncated or invalid.")

    expected_digest = inner_payload[:SHA256_DIGEST_SIZE_BYTES]
    recovered_plaintext = inner_payload[SHA256_DIGEST_SIZE_BYTES:]

    # 4. Perform SHA-256 integrity verification
    actual_digest = hashlib.sha256(recovered_plaintext).digest()
    if actual_digest != expected_digest:
        raise AuthenticationError(
            "Decryption failed: invalid password or corrupted payload."
        )

    return recovered_plaintext
