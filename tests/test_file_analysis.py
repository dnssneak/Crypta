"""
Unit tests for File Analysis & Format Detection module (crypta.forensics.file_analysis).
"""

import tempfile
import unittest
from pathlib import Path
from PIL import Image

from crypta.forensics.file_analysis import inspect_file_properties


class TestFileAnalysis(unittest.TestCase):
    """Test cases for file properties and format consistency checks."""

    def setUp(self):
        """Create temporary test files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

        # 1. Valid PNG
        self.png_path = self.dir_path / "valid.png"
        img = Image.new("RGB", (50, 50), color="blue")
        img.save(self.png_path, format="PNG")

        # 2. JPEG renamed to .png (Mismatch case)
        self.fake_png_path = self.dir_path / "fake_jpeg.png"
        img.save(self.fake_png_path, format="JPEG")

        # 3. Non-image text file
        self.txt_path = self.dir_path / "sample.txt"
        self.txt_path.write_text("Hello World Crypta Forensics")

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_valid_png_properties(self):
        """Valid PNG image file properties and format match."""
        props, fmt = inspect_file_properties(self.png_path)

        self.assertEqual(props.file_name, "valid.png")
        self.assertEqual(props.file_extension, ".png")
        self.assertGreater(props.size_bytes, 0)
        self.assertIsNotNone(props.sha256_hash)
        self.assertEqual(fmt.detected_format, "PNG")
        self.assertTrue(fmt.extension_match)
        self.assertIsNone(fmt.warning)

    def test_format_mismatch_detection(self):
        """JPEG image saved with .png extension is detected as JPEG format mismatch."""
        props, fmt = inspect_file_properties(self.fake_png_path)

        self.assertEqual(fmt.detected_format, "JPEG")
        self.assertEqual(fmt.extension_format, "PNG")
        self.assertFalse(fmt.extension_match)
        self.assertIsNotNone(fmt.warning)
        self.assertIn("extension '.png' does not match", fmt.warning)

    def test_non_image_file_format(self):
        """Text file returns UNKNOWN / NON-IMAGE format."""
        props, fmt = inspect_file_properties(self.txt_path)

        self.assertEqual(fmt.detected_format, "UNKNOWN / NON-IMAGE")
        self.assertFalse(fmt.extension_match)
        self.assertIsNotNone(fmt.warning)

    def test_missing_file_raises_error(self):
        """Missing file path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            inspect_file_properties(self.dir_path / "non_existent.png")


if __name__ == "__main__":
    unittest.main()
