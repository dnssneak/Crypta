"""
End-to-End Integration and Security Unit Tests for Crypta Feature 5 — Secure Pipeline Core.
"""

import os
import shutil
import tempfile
import hashlib
import unittest
from pathlib import Path
from PIL import Image

from crypta.core import (
    hide_file,
    extract_file,
    HideResult,
    ExtractResult,
    CapacityError,
    OutputCollisionError,
)
from crypta.cryptography.exceptions import AuthenticationError


class TestSecurePipelineIntegration(unittest.TestCase):
    """Test suite for Crypta hide/extract pipeline, security controls, and transactional safety."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.password = "Secur3P@ssw0rd!2026"

        # Carrier 1: RGB 200x200 PNG (~15 KB usable capacity)
        self.carrier_rgb = self.temp_path / "carrier_rgb.png"
        img_rgb = Image.new("RGB", (200, 200), color=(100, 150, 200))
        img_rgb.save(self.carrier_rgb, format="PNG")

        # Carrier 2: RGBA 150x150 PNG (~16 KB usable capacity)
        self.carrier_rgba = self.temp_path / "carrier_rgba.png"
        img_rgba = Image.new("RGBA", (150, 150), color=(50, 100, 150, 200))
        img_rgba.save(self.carrier_rgba, format="PNG")

        # Secret file 1: PDF binary data
        self.secret_pdf = self.temp_path / "document.pdf"
        self.pdf_bytes = b"%PDF-1.4\n%BINARY_PDF_DATA_\x00\x01\x02\xFF\xFE\xFD" * 100
        self.secret_pdf.write_bytes(self.pdf_bytes)

        # Secret file 2: ZIP binary data
        self.secret_zip = self.temp_path / "archive.zip"
        self.zip_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00_ZIP_DATA_\x00\xFF" * 80
        self.secret_zip.write_bytes(self.zip_bytes)

        # Secret file 3: EXE binary data
        self.secret_exe = self.temp_path / "app.exe"
        self.exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00_EXE_DATA_\x00\xFF" * 80
        self.secret_exe.write_bytes(self.exe_bytes)

        # Secret file 4: Empty payload (0 bytes)
        self.secret_empty = self.temp_path / "empty.dat"
        self.secret_empty.write_bytes(b"")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_round_trip_rgb_pdf_binary(self):
        """Test end-to-end hide and extract round trip for RGB PNG and PDF binary payload."""
        stego_out = self.temp_path / "stego_pdf.png"
        rec_dir = self.temp_path / "recovered_pdf"
        rec_dir.mkdir()

        # Step 1: Hide
        hide_res = hide_file(self.carrier_rgb, self.secret_pdf, stego_out, self.password)
        self.assertIsInstance(hide_res, HideResult)
        self.assertTrue(stego_out.exists())

        # Step 2: Extract
        ext_res = extract_file(stego_out, self.password, output_destination=rec_dir)
        self.assertIsInstance(ext_res, ExtractResult)
        self.assertTrue(ext_res.output_path.exists())
        self.assertEqual(ext_res.restored_filename, "document.pdf")
        self.assertEqual(ext_res.output_path.read_bytes(), self.pdf_bytes)
        self.assertEqual(ext_res.sha256_hash, hashlib.sha256(self.pdf_bytes).hexdigest())

    def test_round_trip_rgba_channel_preservation(self):
        """Test end-to-end hide and extract with RGBA PNG, verifying 100% Alpha channel preservation."""
        stego_out = self.temp_path / "stego_rgba.png"
        rec_dir = self.temp_path / "recovered_zip"

        # Read original alpha channel values
        with Image.open(self.carrier_rgba) as orig_img:
            orig_alpha = [p[3] for p in orig_img.getdata()]

        # Step 1: Hide
        hide_file(self.carrier_rgba, self.secret_zip, stego_out, self.password)

        # Verify Alpha channel is completely unchanged
        with Image.open(stego_out) as stego_img:
            stego_alpha = [p[3] for p in stego_img.getdata()]
        self.assertEqual(orig_alpha, stego_alpha)

        # Step 2: Extract
        ext_res = extract_file(stego_out, self.password, output_destination=rec_dir)
        self.assertEqual(ext_res.output_path.read_bytes(), self.zip_bytes)

    def test_round_trip_empty_payload(self):
        """Test hiding and extracting an empty file (0 bytes)."""
        stego_out = self.temp_path / "stego_empty.png"
        hide_file(self.carrier_rgb, self.secret_empty, stego_out, self.password)

        ext_res = extract_file(stego_out, self.password, output_destination=self.temp_path / "rec_empty.dat")
        self.assertEqual(ext_res.recovered_size_bytes, 0)
        self.assertEqual(ext_res.output_path.read_bytes(), b"")

    def test_carrier_file_immutability(self):
        """Verify original carrier file on disk is never modified during hiding."""
        carrier_hash_before = hashlib.sha256(self.carrier_rgb.read_bytes()).hexdigest()
        stego_out = self.temp_path / "stego_out.png"

        hide_file(self.carrier_rgb, self.secret_pdf, stego_out, self.password)

        carrier_hash_after = hashlib.sha256(self.carrier_rgb.read_bytes()).hexdigest()
        self.assertEqual(carrier_hash_before, carrier_hash_after)

    def test_repeated_encryption_non_determinism(self):
        """Verify hiding the same file twice produces different stego outputs (fresh salt & nonce)."""
        stego1 = self.temp_path / "stego1.png"
        stego2 = self.temp_path / "stego2.png"

        hide_file(self.carrier_rgb, self.secret_pdf, stego1, self.password)
        hide_file(self.carrier_rgb, self.secret_pdf, stego2, self.password)

        self.assertNotEqual(stego1.read_bytes(), stego2.read_bytes())

    def test_wrong_password_fails_and_leaves_no_output(self):
        """Verify extraction with wrong password raises AuthenticationError and creates no output file."""
        stego_out = self.temp_path / "stego_sec.png"
        hide_file(self.carrier_rgb, self.secret_pdf, stego_out, self.password)

        target_out = self.temp_path / "should_not_exist.pdf"
        with self.assertRaises(AuthenticationError):
            extract_file(stego_out, password="WrongPassword123!", output_destination=target_out)

        self.assertFalse(target_out.exists())

    def test_tampered_ciphertext_fails_safely(self):
        """Verify modifying stego image ciphertext pixels raises AuthenticationError with no recovery file created."""
        stego_out = self.temp_path / "stego_tampered.png"
        hide_file(self.carrier_rgb, self.secret_pdf, stego_out, self.password)

        # Tamper ciphertext pixels on row y=1
        with Image.open(stego_out) as img:
            pixels = img.load()
            for x in range(20):
                r, g, b = pixels[x, 1]
                pixels[x, 1] = (r ^ 1, g ^ 1, b ^ 1)
            img.save(stego_out, format="PNG")

        target_out = self.temp_path / "failed_tampered.pdf"
        with self.assertRaises(AuthenticationError):
            extract_file(stego_out, password=self.password, output_destination=target_out)

        self.assertFalse(target_out.exists())

    def test_insufficient_capacity_rejection(self):
        """Verify error is raised when payload size exceeds carrier capacity."""
        tiny_carrier = self.temp_path / "tiny_carrier.png"
        img_tiny = Image.new("RGB", (10, 10))
        img_tiny.save(tiny_carrier, format="PNG")

        large_secret = self.temp_path / "large_payload.dat"
        large_secret.write_bytes(b"Z" * 5000)

        stego_out = self.temp_path / "tiny_stego.png"

        with self.assertRaises(CapacityError) as cm:
            hide_file(tiny_carrier, large_secret, stego_out, self.password)
        self.assertIn("Insufficient carrier capacity", str(cm.exception))
        self.assertFalse(stego_out.exists())

    def test_output_collision_prevention(self):
        """Verify OutputCollisionError is raised when output file exists and overwrite=False."""
        existing_out = self.temp_path / "existing.png"
        existing_out.write_bytes(b"EXISTING_DATA")

        with self.assertRaises(OutputCollisionError):
            hide_file(self.carrier_rgb, self.secret_pdf, existing_out, self.password, overwrite=False)

    def test_empty_password_rejection(self):
        """Verify empty password raises ValueError."""
        stego_out = self.temp_path / "stego_empty_pwd.png"
        with self.assertRaises(ValueError):
            hide_file(self.carrier_rgb, self.secret_pdf, stego_out, password="")

    def test_non_ascii_unicode_password(self):
        """Verify non-ASCII Unicode passwords work properly throughout hide and extract."""
        unicode_pwd = "🔑_Crypta_Sec_2026_Pässwörd"
        stego_out = self.temp_path / "stego_unicode.png"

        hide_file(self.carrier_rgb, self.secret_exe, stego_out, password=unicode_pwd)
        ext_res = extract_file(stego_out, password=unicode_pwd, output_destination=self.temp_path / "rec_exe.exe")

        self.assertEqual(ext_res.output_path.read_bytes(), self.exe_bytes)


if __name__ == "__main__":
    unittest.main()
