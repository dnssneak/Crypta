"""
Unit tests for Crypta Feature 4 — Binary Payload Framing (Version 2).
"""

import unittest
from crypta.steganography.payload import (
    pack_payload,
    unpack_payload,
    calculate_framed_overhead,
)
from crypta.utils.constants import MAGIC_BYTES, HEADER_VERSION_LEGACY
import struct


class TestPayloadFraming(unittest.TestCase):
    """Test suite for Version 2 payload packing, unpacking, and header validation."""

    def setUp(self):
        self.filename = "secret_archive.zip"
        self.ciphertext = b"\x10\x20\x30\x40\x50\x60\x70\x80" * 20
        self.salt = b"\xAA" * 16
        self.nonce = b"\xBB" * 12

    def test_valid_pack_unpack_v2(self):
        """Test Version 2 payload packing and unpacking."""
        framed = pack_payload(self.filename, self.ciphertext, self.salt, self.nonce)
        self.assertGreater(len(framed), len(self.ciphertext))

        restored_fn, restored_ct, restored_salt, restored_nonce = unpack_payload(framed)
        self.assertEqual(restored_fn, "secret_archive.zip")
        self.assertEqual(restored_ct, self.ciphertext)
        self.assertEqual(restored_salt, self.salt)
        self.assertEqual(restored_nonce, self.nonce)

    def test_path_traversal_sanitization(self):
        """Test path traversal strings are sanitized to basename only."""
        traversal_fn = "../../etc/passwd/malicious_executable.exe"
        framed = pack_payload(traversal_fn, self.ciphertext, self.salt, self.nonce)
        restored_fn, _, _, _ = unpack_payload(framed)
        self.assertEqual(restored_fn, "malicious_executable.exe")

    def test_legacy_v1_payload_rejection(self):
        """Test that legacy Version 1 payload raises ValueError with clear error message."""
        # Construct Version 1 legacy header frame: Magic (8B) + Ver=1 (1B) + FnLen=8 (2B) + filename + CtLen (8B)
        fn_bytes = b"legacy.txt"
        v1_framed = (
            MAGIC_BYTES
            + struct.pack("!BH", HEADER_VERSION_LEGACY, len(fn_bytes))
            + fn_bytes
            + struct.pack("!Q", 10)
            + b"1234567890"
        )
        with self.assertRaises(ValueError) as cm:
            unpack_payload(v1_framed)
        self.assertIn("Legacy unencrypted payload (Version 1) detected", str(cm.exception))

    def test_invalid_magic_header_raises_valueerror(self):
        """Test data without valid magic header raises ValueError."""
        garbage_bytes = b"NOT_A_CRYPTA_HEADER_BYTES_STREAM_DATA_123456"
        with self.assertRaises(ValueError) as cm:
            unpack_payload(garbage_bytes)
        self.assertIn("Crypta payload not found", str(cm.exception))

    def test_calculate_framed_overhead(self):
        """Test calculate_framed_overhead returns exact total overhead bytes outside plaintext."""
        fn = "test.txt"
        overhead = calculate_framed_overhead(fn)
        # Overhead includes header formatting + salt (16B) + nonce (12B) + SHA-256 (32B) + AES-GCM Tag (16B)
        self.assertGreater(overhead, 90)


if __name__ == "__main__":
    unittest.main()
