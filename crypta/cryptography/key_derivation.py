"""
Key Derivation Module for Crypta.
Uses Argon2id to derive a 256-bit AES key from a user password and cryptographically secure salt.
"""

import argon2.low_level as argon2_ll
from crypta.utils.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
    SALT_SIZE_BYTES,
)
from crypta.cryptography.exceptions import EncryptionError


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte (256-bit) encryption key from a password and salt using Argon2id.

    Args:
        password: Plaintext secret password string.
        salt: Cryptographically secure random salt (must be 16 bytes).

    Returns:
        32-byte raw derived key.

    Raises:
        ValueError: If inputs are invalid (e.g. password is not str or salt length != 16).
        EncryptionError: If Argon2id key derivation fails internally.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if not isinstance(salt, bytes):
        raise ValueError("Salt must be bytes.")

    if len(salt) != SALT_SIZE_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes long.")

    password_bytes = password.encode("utf-8")

    try:
        derived_key = argon2_ll.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=argon2_ll.Type.ID,
        )
        return derived_key
    except Exception as err:
        raise EncryptionError(f"Argon2id key derivation failed: {err}") from err
