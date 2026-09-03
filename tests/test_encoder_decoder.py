"""
End-to-end integration tests for Crypta Feature 4 — Encryption & LSB Steganography Pipeline.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image

from crypta.steganography.encoder import embed_payload
from crypta.steganography.decoder import extract_payload
from crypta.cryptography.exceptions import AuthenticationError


class TestEncoderDecoderIntegration(unittest.TestCase):
    """Test suite for end-to-end password encryption, LSB embedding, extraction, and verification."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.password = "ComplexP@ssw0rd!2026"

        # Carrier 1: RGB 200x200 PNG (~15 KB usable capacity)
        self.carrier_rgb = self.temp_path / "carrier_rgb.png"
        img_rgb = Image.new("RGB", (200, 200), color=(100, 150, 200))
        img_rgb.save(self.carrier_rgb, format="PNG")

        # Carrier 2: RGBA 150x150 PNG (~16 KB usable capacity)
        self.carrier_rgba = self.temp_path / "carrier_rgba.png"
        img_rgba = Image.new("RGBA", (150, 150), color=(50, 100, 150, 200))
        img_rgba.save(self.carrier_rgba, format="PNG")

        # Secret file 1: Binary PDF-like content
        self.secret_binary = self.temp_path / "top_secret.pdf"
        self.secret_data = b"%PDF-1.4\n%BINARY_DATA_\x00\x01\x02\xFF\xFE\xFD" * 100
        self.secret_binary.write_bytes(self.secret_data)

        # Secret file 2: Small text file
        self.secret_text = self.temp_path / "notes.txt"
        self.text_data = b"Crypta Encrypted LSB Steganography Test Payload Content."
        self.secret_text.write_bytes(self.text_data)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_round_trip_rgb_binary_payload_encrypted(self):
        """Test end-to-end encrypted hide -> extract round trip with RGB PNG and binary payload."""
        stego_output = self.temp_path / "stego_rgb.png"
        recovered_dir = self.temp_path / "recovered_rgb"
        recovered_dir.mkdir()

        # Step 1: Embed payload with password encryption
        stego_path = embed_payload(
            self.carrier_rgb, self.secret_binary, stego_output, password=self.password
        )
        self.assertTrue(stego_path.exists())

        # Step 2: Extract payload with correct password
        out_file, restored_fn, payload_size = extract_payload(
            stego_path, password=self.password, output_destination=recovered_dir
        )

        self.assertTrue(out_file.exists())
        self.assertEqual(restored_fn, "top_secret.pdf")
        self.assertEqual(payload_size, len(self.secret_data))

        # Step 3: Byte-for-byte exact equality check
        recovered_data = out_file.read_bytes()
        self.assertEqual(recovered_data, self.secret_data)

    def test_round_trip_rgba_text_payload_encrypted(self):
        """Test end-to-end encrypted hide -> extract round trip with RGBA PNG and text payload."""
        stego_output = self.temp_path / "stego_rgba.png"
        recovered_file = self.temp_path / "recovered_notes.txt"

        # Step 1: Embed payload
        stego_path = embed_payload(
            self.carrier_rgba, self.secret_text, stego_output, password=self.password
        )
        self.assertTrue(stego_path.exists())

        # Step 2: Extract payload directly to specified file path
        out_file, restored_fn, payload_size = extract_payload(
            stego_path, password=self.password, output_destination=recovered_file
        )

        self.assertEqual(out_file, recovered_file)
        self.assertEqual(restored_fn, "notes.txt")
        self.assertEqual(out_file.read_bytes(), self.text_data)

    def test_extraction_with_wrong_password_fails(self):
        """Verify extraction with an incorrect password raises AuthenticationError."""
        stego_output = self.temp_path / "stego_wrong_pwd.png"
        embed_payload(
            self.carrier_rgb, self.secret_text, stego_output, password=self.password
        )

        with self.assertRaises(AuthenticationError):
            extract_payload(stego_output, password="WrongPassword123!")

    def test_tampered_stego_image_rejection(self):
        """Verify modifying stego image pixels causes authentication failure upon extraction."""
        stego_output = self.temp_path / "stego_tampered.png"
        embed_payload(
            self.carrier_rgb, self.secret_text, stego_output, password=self.password
        )

        # Tamper ciphertext payload bits stored in image LSBs on row y=1 (pure ciphertext data)
        with Image.open(stego_output) as img:
            pixels = img.load()
            for x in range(20):
                r, g, b = pixels[x, 1]
                pixels[x, 1] = (r ^ 1, g ^ 1, b ^ 1)
            img.save(stego_output, format="PNG")

        with self.assertRaises(AuthenticationError):
            extract_payload(stego_output, password=self.password)

    def test_original_carrier_not_modified(self):
        """Verify original carrier file on disk is never modified during embedding."""
        carrier_bytes_before = self.carrier_rgb.read_bytes()
        stego_output = self.temp_path / "stego_out.png"

        embed_payload(
            self.carrier_rgb, self.secret_text, stego_output, password=self.password
        )

        carrier_bytes_after = self.carrier_rgb.read_bytes()
        self.assertEqual(carrier_bytes_before, carrier_bytes_after)

    def test_insufficient_capacity_rejection(self):
        """Verify error is raised when payload size exceeds carrier capacity."""
        tiny_carrier = self.temp_path / "tiny_carrier.png"
        img_tiny = Image.new("RGB", (10, 10))
        img_tiny.save(tiny_carrier, format="PNG")

        large_secret = self.temp_path / "large_payload.dat"
        large_secret.write_bytes(b"Z" * 5000)

        stego_out = self.temp_path / "tiny_stego.png"

        with self.assertRaises(ValueError) as cm:
            embed_payload(
                tiny_carrier, large_secret, stego_out, password=self.password
            )
        self.assertIn("Insufficient carrier capacity", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
