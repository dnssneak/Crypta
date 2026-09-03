"""
Unit tests for SHA-256 Hashing & Fingerprinting module (crypta.forensics.hashing).
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from crypta.forensics.hashing import calculate_sha256


class TestHashing(unittest.TestCase):
    """Test cases for SHA-256 chunked calculation."""

    def setUp(self):
        """Create temporary test directory."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_known_data_sha256(self):
        """Verify SHA-256 digest matches hashlib standard output."""
        data = b"Crypta Forensics Test Binary Data 12345"
        expected = hashlib.sha256(data).hexdigest()

        file_path = self.dir_path / "test.bin"
        file_path.write_bytes(data)

        digest = calculate_sha256(file_path)
        self.assertEqual(digest, expected)

    def test_empty_file_sha256(self):
        """Verify empty file SHA-256 hash."""
        expected = hashlib.sha256(b"").hexdigest()
        file_path = self.dir_path / "empty.bin"
        file_path.write_bytes(b"")

        digest = calculate_sha256(file_path)
        self.assertEqual(digest, expected)

    def test_chunked_reading_large_file(self):
        """Verify chunked reading matches single-pass hash on 1 MB file."""
        data = b"A" * (1024 * 1024)
        expected = hashlib.sha256(data).hexdigest()

        file_path = self.dir_path / "large.bin"
        file_path.write_bytes(data)

        # Test small chunk_size to force multiple loop iterations
        digest = calculate_sha256(file_path, chunk_size=4096)
        self.assertEqual(digest, expected)

    def test_missing_file_raises_error(self):
        """Non-existent file path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            calculate_sha256(self.dir_path / "non_existent.bin")

    def test_directory_raises_error(self):
        """Directory path raises ValueError."""
        with self.assertRaises(ValueError):
            calculate_sha256(self.dir_path)


if __name__ == "__main__":
    unittest.main()
