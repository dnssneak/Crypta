"""
Integration tests for Crypta Steganalysis Engine (crypta.steganalysis).
Tests end-to-end analysis on clean vs stego PNG images, RGBA images, invalid formats, and visualization.
"""

import os
import tempfile
import unittest
from pathlib import Path
from PIL import Image

from crypta.steganography import embed_payload
from crypta.core import hide_file
from crypta.steganalysis import analyze_image, AnalysisResult


class TestSteganalysisIntegration(unittest.TestCase):
    """End-to-end integration tests for steganalysis engine."""

    def setUp(self):
        """Create temporary test directory and test images."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

        # 1. Create clean RGB PNG image
        self.clean_rgb_path = self.dir_path / "clean_rgb.png"
        img_rgb = Image.new("RGB", (100, 100), color=(120, 140, 160))
        img_rgb.save(self.clean_rgb_path)

        # 2. Create clean RGBA PNG image
        self.clean_rgba_path = self.dir_path / "clean_rgba.png"
        img_rgba = Image.new("RGBA", (100, 100), color=(120, 140, 160, 255))
        img_rgba.save(self.clean_rgba_path)

        # 3. Create stego RGB PNG image using Feature 5 hide_file pipeline
        self.secret_path = self.dir_path / "secret.txt"
        self.secret_path.write_bytes(b"Confidential payload for steganalysis testing!")

        self.stego_rgb_path = self.dir_path / "stego_rgb.png"
        hide_file(
            carrier_path=self.clean_rgb_path,
            secret_path=self.secret_path,
            output_path=self.stego_rgb_path,
            password="SecurePassword123!",
            overwrite=True,
        )

        # 4. Create non-PNG file (JPEG)
        self.jpeg_path = self.dir_path / "test.jpg"
        img_rgb.save(self.jpeg_path, format="JPEG")

        # 5. Create text file pretending to be image
        self.txt_path = self.dir_path / "fake.png"
        self.txt_path.write_text("This is not an image file.")

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_analyze_clean_rgb_image(self):
        """Analyze clean RGB PNG image successfully."""
        res = analyze_image(self.clean_rgb_path)

        self.assertIsInstance(res, AnalysisResult)
        self.assertEqual(res.image_info.mode, "RGB")
        self.assertEqual(res.image_info.analyzed_channels, ["R", "G", "B"])
        self.assertFalse(res.image_info.alpha_excluded)

        # Check structured outputs
        self.assertGreaterEqual(res.entropy.overall_entropy, 0.0)
        self.assertIn("R", res.lsb_analysis.zero_counts)
        self.assertIn("G", res.chi_square.statistics)
        self.assertIn("B", res.histogram.channel_stats)
        self.assertEqual(res.pixel_statistics.total_pixels, 10000)

        # JSON dictionary export
        res_dict = res.to_dict()
        self.assertIsInstance(res_dict, dict)
        self.assertIn("image_info", res_dict)
        self.assertIn("entropy", res_dict)

    def test_analyze_stego_rgb_image(self):
        """Analyze stego RGB PNG image embedded with Crypta payload."""
        res = analyze_image(self.stego_rgb_path)

        self.assertIsInstance(res, AnalysisResult)
        self.assertEqual(res.image_info.mode, "RGB")
        self.assertGreater(res.entropy.overall_entropy, 0.0)
        self.assertIn("R", res.lsb_analysis.deviations)

    def test_analyze_rgba_alpha_exclusion(self):
        """Analyze RGBA PNG image and verify Alpha channel is excluded from LSB steganalysis."""
        res = analyze_image(self.clean_rgba_path)

        self.assertEqual(res.image_info.mode, "RGBA")
        self.assertEqual(res.image_info.analyzed_channels, ["R", "G", "B"])
        self.assertTrue(res.image_info.alpha_excluded)
        self.assertNotIn("A", res.lsb_analysis.zero_counts)
        self.assertNotIn("A", res.chi_square.statistics)

    def test_visualization_generation(self):
        """Test analyze_image with visualize=True generates PNG chart."""
        chart_dest = self.dir_path / "chart.png"
        res = analyze_image(self.stego_rgb_path, visualize=True, visualization_output=chart_dest)

        self.assertTrue(chart_dest.exists())
        self.assertGreater(chart_dest.stat().st_size, 0)

    def test_invalid_image_format_rejection(self):
        """JPEG image is rejected by carrier validation."""
        with self.assertRaises(ValueError) as ctx:
            analyze_image(self.jpeg_path)
        self.assertIn("PNG", str(ctx.exception))

    def test_corrupted_fake_image_rejection(self):
        """Corrupted fake PNG image is rejected gracefully."""
        with self.assertRaises(ValueError):
            analyze_image(self.txt_path)

    def test_missing_file_raises_error(self):
        """Non-existent image path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            analyze_image(self.dir_path / "non_existent.png")


if __name__ == "__main__":
    unittest.main()
