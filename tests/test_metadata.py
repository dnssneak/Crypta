"""
Unit tests for Metadata & Terminal Safety module (crypta.forensics.metadata).
"""

import tempfile
import unittest
from pathlib import Path
from PIL import Image, PngImagePlugin

from crypta.forensics.metadata import sanitize_metadata_text, extract_image_metadata


class TestMetadata(unittest.TestCase):
    """Test cases for metadata extraction and terminal control sequence sanitization."""

    def setUp(self):
        """Create temporary test images with and without metadata."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

        # 1. Image with PNG text metadata
        self.meta_png_path = self.dir_path / "meta.png"
        img = Image.new("RGB", (20, 20), color="green")
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("Author", "Crypta Security Team")
        png_info.add_text("Description", "Forensics metadata test image")
        img.save(self.meta_png_path, pnginfo=png_info)

        # 2. Image without metadata
        self.clean_png_path = self.dir_path / "clean.png"
        img_clean = Image.new("RGB", (20, 20), color="red")
        img_clean.save(self.clean_png_path)

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_sanitize_terminal_control_codes(self):
        """Sanitize function removes ANSI escape sequences and non-printable control characters."""
        malicious = "Malicious\x1b[31m Text\x07\x00\x1f Data"
        clean = sanitize_metadata_text(malicious)

        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\x07", clean)
        self.assertNotIn("\x00", clean)
        self.assertEqual(clean, "Malicious[31m Text Data")

    def test_png_text_metadata_extraction(self):
        """Extract PNG text metadata fields correctly."""
        img_props, meta = extract_image_metadata(self.meta_png_path)

        self.assertEqual(img_props.width, 20)
        self.assertEqual(img_props.height, 20)
        self.assertEqual(img_props.mode, "RGB")
        self.assertEqual(img_props.channels, 3)

        self.assertGreaterEqual(meta.text_entry_count, 2)
        self.assertIn("Author", meta.text_metadata)
        self.assertEqual(meta.text_metadata["Author"], "Crypta Security Team")
        self.assertIn("Description", meta.text_metadata)
        self.assertEqual(meta.text_metadata["Description"], "Forensics metadata test image")

    def test_clean_png_metadata_extraction(self):
        """Image without metadata reports zero text entries and EXIF Not Present."""
        img_props, meta = extract_image_metadata(self.clean_png_path)

        self.assertFalse(meta.exif_present)
        self.assertEqual(meta.text_entry_count, 0)
        self.assertIn("EXIF Not Present", meta.summary)


if __name__ == "__main__":
    unittest.main()
