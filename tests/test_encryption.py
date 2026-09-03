"""
Unit tests for Crypta Feature 4 — AES-256-GCM Encryption.
"""

import unittest
from crypta.cryptography.encryption import encrypt_data, EncryptionResult


class TestEncryption(unittest.TestCase):
    """Test suite for AES-256-GCM encryption module."""

    def setUp(self):
        self.password = "SecurePassword2026$"
        self.plaintext = b"Top secret payload bytes stream"

    def test_successful_encryption_returns_encryption_result(self):
        """Test encrypt_data returns a valid EncryptionResult object."""
        result = encrypt_data(self.plaintext, self.password)
        self.assertIsInstance(result, EncryptionResult)
        self.assertEqual(len(result.salt), 16)
        self.assertEqual(len(result.nonce), 12)
        self.assertGreater(len(result.ciphertext), len(self.plaintext))
        self.assertNotEqual(result.ciphertext, self.plaintext)

    def test_repeated_encryption_produces_unique_salt_nonce_and_ciphertext(self):
        """Test encryption generates fresh salt and nonce every time (non-deterministic output)."""
        res1 = encrypt_data(self.plaintext, self.password)
        res2 = encrypt_data(self.plaintext, self.password)

        self.assertNotEqual(res1.salt, res2.salt)
        self.assertNotEqual(res1.nonce, res2.nonce)
        self.assertNotEqual(res1.ciphertext, res2.ciphertext)

    def test_binary_payloads_with_null_bytes_and_high_bits(self):
        """Test binary data containing null bytes (0x00) and high-bit values (0xFF) encrypts properly."""
        binary_data = bytes(range(256)) * 4
        result = encrypt_data(binary_data, self.password)
        self.assertIsInstance(result, EncryptionResult)
        self.assertGreater(len(result.ciphertext), len(binary_data))

    def test_empty_plaintext_payload(self):
        """Test encrypting empty payload (0 bytes) works properly."""
        empty_data = b""
        result = encrypt_data(empty_data, self.password)
        self.assertIsInstance(result, EncryptionResult)
        # Should contain inner SHA-256 (32B) + AES-GCM Auth Tag (16B) = 48B
        self.assertEqual(len(result.ciphertext), 48)

    def test_invalid_input_types_raise_value_error(self):
        """Test passing invalid types raises ValueError."""
        with self.assertRaises(ValueError):
            encrypt_data("not_bytes", self.password)

        with self.assertRaises(ValueError):
            encrypt_data(b"valid_bytes", 12345)


if __name__ == "__main__":
    unittest.main()
