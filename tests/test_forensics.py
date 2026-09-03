"""
Integration tests for Crypta Forensics Engine (crypta.forensics).
Tests end-to-end forensic analysis, PNG header parsing, format mismatch, and read-only file immutability.
"""

import tempfile
import unittest
from pathlib import Path
from PIL import Image

from crypta.forensics.hashing import calculate_sha256
from crypta.forensics.analyzer import analyze_forensics
from crypta.forensics.results import ForensicResult


class TestForensicsIntegration(unittest.TestCase):
    """End-to-end integration tests for forensics engine."""

    def setUp(self):
        """Create temporary test files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

        # 1. Valid RGB PNG
        self.rgb_png_path = self.dir_path / "test_rgb.png"
        img_rgb = Image.new("RGB", (64, 64), color=(100, 150, 200))
        img_rgb.save(self.rgb_png_path, format="PNG")

        # 2. Valid RGBA PNG
        self.rgba_png_path = self.dir_path / "test_rgba.png"
        img_rgba = Image.new("RGBA", (64, 64), color=(100, 150, 200, 255))
        img_rgba.save(self.rgba_png_path, format="PNG")

        # 3. JPEG file saved with .png extension (Extension mismatch)
        self.fake_png_path = self.dir_path / "fake_jpg.png"
        img_rgb.save(self.fake_png_path, format="JPEG")

        # 4. Text file
        self.txt_path = self.dir_path / "corrupt.png"
        self.txt_path.write_text("Not an image")

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_analyze_forensics_rgb_png(self):
        """End-to-end forensic analysis on valid RGB PNG."""
        res = analyze_forensics(self.rgb_png_path)

        self.assertIsInstance(res, ForensicResult)
        self.assertEqual(res.file.file_name, "test_rgb.png")
        self.assertEqual(res.format.detected_format, "PNG")
        self.assertTrue(res.format.extension_match)

        self.assertEqual(res.image.width, 64)
        self.assertEqual(res.image.height, 64)
        self.assertEqual(res.image.mode, "RGB")
        self.assertEqual(res.image.channels, 3)

        self.assertIsNotNone(res.png_structure)
        self.assertTrue(res.png_structure.signature_valid)
        self.assertEqual(res.png_structure.bit_depth, 8)
        self.assertEqual(res.png_structure.color_type_desc, "Truecolor (RGB)")

        # Dict export test
        res_dict = res.to_dict()
        self.assertIsInstance(res_dict, dict)
        self.assertIn("file", res_dict)
        self.assertIn("png_structure", res_dict)

    def test_analyze_forensics_rgba_png(self):
        """End-to-end forensic analysis on valid RGBA PNG."""
        res = analyze_forensics(self.rgba_png_path)

        self.assertEqual(res.image.mode, "RGBA")
        self.assertEqual(res.image.channels, 4)
        self.assertIsNotNone(res.png_structure)
        self.assertEqual(res.png_structure.color_type_desc, "Truecolor with Alpha (RGBA)")

    def test_format_mismatch_warning(self):
        """JPEG image saved with .png extension produces format mismatch warning."""
        res = analyze_forensics(self.fake_png_path)

        self.assertEqual(res.format.detected_format, "JPEG")
        self.assertFalse(res.format.extension_match)
        self.assertGreater(len(res.warnings), 0)

    def test_file_immutability_guarantee(self):
        """Forensic analysis strictly preserves original file hash (read-only verification)."""
        initial_hash = calculate_sha256(self.rgb_png_path)

        # Run full forensic analysis
        res = analyze_forensics(self.rgb_png_path)

        # Re-calculate hash after analysis
        post_hash = calculate_sha256(self.rgb_png_path)

        self.assertEqual(initial_hash, res.file.sha256_hash)
        self.assertEqual(initial_hash, post_hash)


if __name__ == "__main__":
    unittest.main()
