"""
Unit tests for Crypta Feature 2 — Carrier Image Validation Engine.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image

from crypta.steganography.validators import validate_carrier_image
from crypta.steganography.carrier import CarrierImage


class TestCarrierImageValidation(unittest.TestCase):
    """Test suite for validate_carrier_image function."""

    def setUp(self):
        """Create temporary test directory and test images."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

        # 1. Valid RGB PNG (100x100)
        self.rgb_png = self.temp_path / "test_rgb.png"
        img_rgb = Image.new("RGB", (100, 100), color=(255, 0, 0))
        img_rgb.save(self.rgb_png, format="PNG")

        # 2. Valid RGBA PNG (50x50)
        self.rgba_png = self.temp_path / "test_rgba.png"
        img_rgba = Image.new("RGBA", (50, 50), color=(0, 255, 0, 128))
        img_rgba.save(self.rgba_png, format="PNG")

        # 3. Invalid format JPEG
        self.jpeg_file = self.temp_path / "test_image.jpg"
        img_jpeg = Image.new("RGB", (100, 100), color=(0, 0, 255))
        img_jpeg.save(self.jpeg_file, format="JPEG")

        # 4. JPEG renamed as .png (Format mismatch)
        self.fake_png = self.temp_path / "fake.png"
        img_jpeg.save(self.fake_png, format="JPEG")

        # 5. Unsupported mode Palette PNG ('P')
        self.palette_png = self.temp_path / "test_palette.png"
        img_p = Image.new("P", (10, 10))
        img_p.save(self.palette_png, format="PNG")

        # 6. Corrupted file
        self.corrupted_png = self.temp_path / "corrupted.png"
        with open(self.corrupted_png, "wb") as f:
            f.write(b"NOT_A_REAL_PNG_IMAGE_HEADER_DATA_STREAM")

    def tearDown(self):
        """Remove temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_valid_rgb_png(self):
        """Test successful validation of RGB PNG image."""
        carrier = validate_carrier_image(self.rgb_png)
        self.assertIsInstance(carrier, CarrierImage)
        self.assertEqual(carrier.format, "PNG")
        self.assertEqual(carrier.mode, "RGB")
        self.assertEqual(carrier.channels, 3)
        self.assertEqual(carrier.width, 100)
        self.assertEqual(carrier.height, 100)
        self.assertEqual(carrier.dimensions_str, "100 × 100")
        self.assertEqual(carrier.total_pixels, 10000)

    def test_valid_rgba_png(self):
        """Test successful validation of RGBA PNG image."""
        carrier = validate_carrier_image(self.rgba_png)
        self.assertIsInstance(carrier, CarrierImage)
        self.assertEqual(carrier.format, "PNG")
        self.assertEqual(carrier.mode, "RGBA")
        self.assertEqual(carrier.channels, 4)
        self.assertEqual(carrier.width, 50)
        self.assertEqual(carrier.height, 50)

    def test_missing_file_raises_filenotfound(self):
        """Test missing file path raises FileNotFoundError."""
        missing = self.temp_path / "non_existent.png"
        with self.assertRaises(FileNotFoundError):
            validate_carrier_image(missing)

    def test_directory_raises_valueerror(self):
        """Test directory path raises ValueError."""
        with self.assertRaises(ValueError):
            validate_carrier_image(self.temp_dir)

    def test_non_png_raises_valueerror(self):
        """Test JPEG image raises ValueError for unsupported format."""
        with self.assertRaises(ValueError) as cm:
            validate_carrier_image(self.jpeg_file)
        self.assertIn("Unsupported carrier format", str(cm.exception))

    def test_fake_png_extension_raises_valueerror(self):
        """Test JPEG file renamed to .png is detected by Pillow format inspection."""
        with self.assertRaises(ValueError) as cm:
            validate_carrier_image(self.fake_png)
        self.assertIn("Unsupported carrier format", str(cm.exception))

    def test_unsupported_mode_raises_valueerror(self):
        """Test Palette ('P') mode PNG raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            validate_carrier_image(self.palette_png)
        self.assertIn("Unsupported image color mode", str(cm.exception))

    def test_corrupted_png_raises_valueerror(self):
        """Test corrupted image file raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            validate_carrier_image(self.corrupted_png)
        self.assertIn("Invalid or corrupted image", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
