"""
Unit tests for Pixel-Level Analysis module (crypta.steganalysis.pixel_analysis).
"""

import unittest
import numpy as np
from crypta.steganalysis.pixel_analysis import calculate_lsb_transition_frequency, analyze_pixels


class TestPixelAnalysis(unittest.TestCase):
    """Test cases for pixel statistics and spatial LSB transition rates."""

    def test_lsb_transition_frequency_constant_array(self):
        """Constant array has 0.0 LSB transition rate."""
        arr = np.full(100, 10, dtype=np.uint8) # all LSB 0
        rate = calculate_lsb_transition_frequency(arr)
        self.assertEqual(rate, 0.0)

    def test_lsb_transition_frequency_alternating_array(self):
        """Alternating LSB array [0, 1, 0, 1] has 1.0 LSB transition rate."""
        arr = np.tile([0, 1], 50).astype(np.uint8)
        rate = calculate_lsb_transition_frequency(arr)
        self.assertEqual(rate, 1.0)

    def test_lsb_transition_frequency_random_array(self):
        """Independent random bit array has transition rate near 0.50."""
        np.random.seed(42)
        arr = np.random.randint(0, 256, 10000, dtype=np.uint8)
        rate = calculate_lsb_transition_frequency(arr)
        self.assertAlmostEqual(rate, 0.50, delta=0.03)

    def test_analyze_pixels_unique_counts_and_dimensions(self):
        """Test total_pixels and unique value counts on 10x20 image."""
        img = np.zeros((10, 20, 3), dtype=np.uint8)
        img[:, :, 0] = 5    # R: 1 unique value
        img[:5, :, 1] = 10  # G: 2 unique values
        img[5:, :, 1] = 20

        res = analyze_pixels(img, ["R", "G", "B"])

        self.assertEqual(res.total_pixels, 200)
        self.assertEqual(res.unique_values["R"], 1)
        self.assertEqual(res.unique_values["G"], 2)
        self.assertIn("R", res.lsb_transition_frequencies)


if __name__ == "__main__":
    unittest.main()
