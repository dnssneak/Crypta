"""
Unit tests for Crypta Feature 4 — Argon2id Key Derivation.
"""

import unittest
from crypta.cryptography.key_derivation import derive_key


class TestKeyDerivation(unittest.TestCase):
    """Test suite for Argon2id key derivation module."""

    def setUp(self):
        self.password = "SuperSecretPassword123!"
        self.salt = b"\x01" * 16

    def test_same_password_and_salt_produces_identical_key(self):
        """Test key derivation is deterministic for fixed password and salt."""
        key1 = derive_key(self.password, self.salt)
        key2 = derive_key(self.password, self.salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_different_salt_produces_different_key(self):
        """Test different salt produces a different 32-byte key."""
        salt2 = b"\x02" * 16
        key1 = derive_key(self.password, self.salt)
        key2 = derive_key(self.password, salt2)
        self.assertNotEqual(key1, key2)

    def test_different_password_produces_different_key(self):
        """Test different password with same salt produces a different key."""
        key1 = derive_key("Password123", self.salt)
        key2 = derive_key("Password124", self.salt)
        self.assertNotEqual(key1, key2)

    def test_non_ascii_unicode_passwords(self):
        """Test non-ASCII Unicode passwords are properly handled using UTF-8."""
        key1 = derive_key("Pässwörd_🔒_Key", self.salt)
        key2 = derive_key("Pässwörd_🔒_Key", self.salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_invalid_salt_length_raises_value_error(self):
        """Test salt length other than 16 bytes raises ValueError."""
        with self.assertRaises(ValueError):
            derive_key(self.password, b"short_salt")

    def test_invalid_password_type_raises_value_error(self):
        """Test non-string password type raises ValueError."""
        with self.assertRaises(ValueError):
            derive_key(12345, self.salt)


if __name__ == "__main__":
    unittest.main()
