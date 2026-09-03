"""
Unit tests for Crypta Feature 2 — Capacity Engine.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from crypta.steganography.carrier import CarrierImage
from crypta.steganography.capacity import (
    DEFAULT_PAYLOAD_OVERHEAD_BYTES,
    calculate_raw_capacity_bits,
    calculate_raw_capacity_bytes,
    calculate_usable_capacity_bytes,
    get_payload_size,
    check_payload_fit,
    format_size_bytes,
)


class TestCapacityEngine(unittest.TestCase):
    """Test suite for capacity calculation and fit verification."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

        # Mock RGB 100x100 carrier
        self.carrier_rgb = CarrierImage(
            path=self.temp_path / "mock_rgb.png",
            format="PNG",
            width=100,
            height=100,
            mode="RGB",
            channels=3,
            file_size_bytes=5000,
        )

        # Mock RGBA 50x50 carrier
        self.carrier_rgba = CarrierImage(
            path=self.temp_path / "mock_rgba.png",
            format="PNG",
            width=50,
            height=50,
            mode="RGBA",
            channels=4,
            file_size_bytes=3000,
        )

        # Tiny 1x1 carrier
        self.carrier_tiny = CarrierImage(
            path=self.temp_path / "tiny.png",
            format="PNG",
            width=1,
            height=1,
            mode="RGB",
            channels=3,
            file_size_bytes=100,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_raw_and_usable_capacity_calculations(self):
        """Test bits, bytes, raw, and net usable capacity calculations."""
        # 100 * 100 * 3 = 30,000 bits -> 3,750 bytes
        raw_bits_rgb = calculate_raw_capacity_bits(self.carrier_rgb)
        raw_bytes_rgb = calculate_raw_capacity_bytes(self.carrier_rgb)
        usable_bytes_rgb = calculate_usable_capacity_bytes(self.carrier_rgb, 256)

        self.assertEqual(raw_bits_rgb, 30000)
        self.assertEqual(raw_bytes_rgb, 3750)
        self.assertEqual(usable_bytes_rgb, 3750 - 256)

        # 50 * 50 * 4 = 10,000 bits -> 1,250 bytes
        raw_bits_rgba = calculate_raw_capacity_bits(self.carrier_rgba)
        raw_bytes_rgba = calculate_raw_capacity_bytes(self.carrier_rgba)
        usable_bytes_rgba = calculate_usable_capacity_bytes(self.carrier_rgba, 256)

        self.assertEqual(raw_bits_rgba, 10000)
        self.assertEqual(raw_bytes_rgba, 1250)
        self.assertEqual(usable_bytes_rgba, 1250 - 256)

    def test_payload_size_calculation(self):
        """Test get_payload_size retrieves exact file byte size."""
        payload_file = self.temp_path / "secret.dat"
        payload_data = b"X" * 1024
        with open(payload_file, "wb") as f:
            f.write(payload_data)

        size = get_payload_size(payload_file)
        self.assertEqual(size, 1024)

    def test_check_payload_fit_scenarios(self):
        """Test check_payload_fit for fitting, boundary, and exceeding payload sizes."""
        usable_capacity = calculate_usable_capacity_bytes(self.carrier_rgb, 256)  # 3494 bytes

        # Scenario 1: Payload easily fits (1000 bytes)
        fits, required, available = check_payload_fit(self.carrier_rgb, 1000, 256)
        self.assertTrue(fits)
        self.assertEqual(required, 1000 + 256)
        self.assertEqual(available, usable_capacity)

        # Scenario 2: Payload exactly at usable capacity limit
        fits_exact, required_exact, _ = check_payload_fit(self.carrier_rgb, usable_capacity, 256)
        self.assertTrue(fits_exact)
        self.assertEqual(required_exact, usable_capacity + 256)

        # Scenario 3: Payload 1 byte over usable capacity limit
        fits_over, required_over, _ = check_payload_fit(self.carrier_rgb, usable_capacity + 1, 256)
        self.assertFalse(fits_over)
        self.assertEqual(required_over, usable_capacity + 1 + 256)

    def test_edge_case_tiny_image(self):
        """Test tiny 1x1 image capacity behavior (3 bits = 0 bytes)."""
        raw_bytes = calculate_raw_capacity_bytes(self.carrier_tiny)
        usable_bytes = calculate_usable_capacity_bytes(self.carrier_tiny, 256)

        self.assertEqual(raw_bytes, 0)
        self.assertEqual(usable_bytes, 0)

        fits, _, _ = check_payload_fit(self.carrier_tiny, 10, 256)
        self.assertFalse(fits)

    def test_format_size_bytes_strings(self):
        """Test human readable size formatting function."""
        self.assertEqual(format_size_bytes(500), "500 Bytes")
        self.assertIn("1.00 KiB", format_size_bytes(1024))
        self.assertIn("1.00 MiB", format_size_bytes(1024 * 1024))


if __name__ == "__main__":
    unittest.main()
