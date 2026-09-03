"""
Unit tests for Crypta Feature 4 — AES-256-GCM Decryption and Integrity Verification.
"""

import unittest
from crypta.cryptography.encryption import encrypt_data
from crypta.cryptography.decryption import decrypt_data
from crypta.cryptography.exceptions import AuthenticationError, DecryptionError


class TestDecryption(unittest.TestCase):
    """Test suite for AES-256-GCM decryption and integrity verification."""

    def setUp(self):
        self.password = "CorrectHorseBatteryStaple!"
        self.plaintext = b"Confidential document content for round trip testing.\x00\xFF"
        self.enc_result = encrypt_data(self.plaintext, self.password)

    def test_successful_decryption_round_trip(self):
        """Test decrypting with correct password recovers exact original bytes."""
        recovered = decrypt_data(
            self.enc_result.ciphertext,
            self.password,
            self.enc_result.salt,
            self.enc_result.nonce,
        )
        self.assertEqual(recovered, self.plaintext)

    def test_incorrect_password_raises_authentication_error(self):
        """Test decrypting with incorrect password raises AuthenticationError."""
        with self.assertRaises(AuthenticationError) as cm:
            decrypt_data(
                self.enc_result.ciphertext,
                "WrongPassword123!",
                self.enc_result.salt,
                self.enc_result.nonce,
            )
        self.assertIn("invalid password or corrupted payload", str(cm.exception))

    def test_modified_ciphertext_raises_authentication_error(self):
        """Test flipping a single bit in ciphertext fails AES-GCM authentication."""
        ct_bytes = bytearray(self.enc_result.ciphertext)
        ct_bytes[0] ^= 0x01  # Flip one bit in first byte
        tampered_ciphertext = bytes(ct_bytes)

        with self.assertRaises(AuthenticationError) as cm:
            decrypt_data(
                tampered_ciphertext,
                self.password,
                self.enc_result.salt,
                self.enc_result.nonce,
            )
        self.assertIn("invalid password or corrupted payload", str(cm.exception))

    def test_modified_nonce_raises_authentication_error(self):
        """Test modified nonce causes decryption/authentication failure."""
        tampered_nonce = b"\x00" * 12
        with self.assertRaises(AuthenticationError):
            decrypt_data(
                self.enc_result.ciphertext,
                self.password,
                self.enc_result.salt,
                tampered_nonce,
            )

    def test_modified_salt_raises_authentication_error(self):
        """Test modified salt causes key mismatch and authentication failure."""
        tampered_salt = b"\x00" * 16
        with self.assertRaises(AuthenticationError):
            decrypt_data(
                self.enc_result.ciphertext,
                self.password,
                tampered_salt,
                self.enc_result.nonce,
            )

    def test_truncated_ciphertext_raises_error(self):
        """Test truncated ciphertext raises AuthenticationError or DecryptionError."""
        truncated_ct = self.enc_result.ciphertext[:10]
        with self.assertRaises((AuthenticationError, DecryptionError)):
            decrypt_data(
                truncated_ct,
                self.password,
                self.enc_result.salt,
                self.enc_result.nonce,
            )


if __name__ == "__main__":
    unittest.main()
