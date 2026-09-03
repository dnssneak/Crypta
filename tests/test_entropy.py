"""
Unit tests for Shannon Entropy Analysis module (crypta.steganalysis.entropy).
"""

import unittest
import numpy as np
from crypta.steganalysis.entropy import calculate_shannon_entropy, analyze_entropy


class TestEntropyAnalysis(unittest.TestCase):
    """Test cases for Shannon entropy calculation and analysis."""

    def test_uniform_array_entropy_is_zero(self):
        """Array with single repeated value has 0.0 entropy."""
        arr = np.full((100, 100), fill_value=42, dtype=np.uint8)
        entropy = calculate_shannon_entropy(arr)
        self.assertEqual(entropy, 0.0)

    def test_two_equally_likely_values_entropy_is_one(self):
        """Array with two equal frequency values has exactly 1.0 bit entropy."""
        arr = np.array([0, 0, 255, 255], dtype=np.uint8)
        entropy = calculate_shannon_entropy(arr)
        self.assertAlmostEqual(entropy, 1.0, places=4)

    def test_maximum_entropy_256_uniform_values(self):
        """Array with uniform distribution of all 256 byte values has 8.0 bits entropy."""
        arr = np.tile(np.arange(256, dtype=np.uint8), 100)
        entropy = calculate_shannon_entropy(arr)
        self.assertAlmostEqual(entropy, 8.0, places=4)

    def test_empty_array_entropy(self):
        """Empty array returns 0.0 entropy safely without error."""
        arr = np.array([], dtype=np.uint8)
        entropy = calculate_shannon_entropy(arr)
        self.assertEqual(entropy, 0.0)

    def test_analyze_entropy_rgb_image(self):
        """Test analyze_entropy on synthetic 3D RGB image array."""
        # Create 10x10 RGB image with uniform R, two-val G, random B
        img = np.zeros((10, 10, 3), dtype=np.uint8)
        img[:, :, 0] = 100  # R: uniform -> entropy 0.0
        img[:5, :, 1] = 0   # G: half 0, half 255 -> entropy 1.0
        img[5:, :, 1] = 255
        np.random.seed(42)
        img[:, :, 2] = np.random.randint(0, 256, (10, 10), dtype=np.uint8) # B: random

        res = analyze_entropy(img, ["R", "G", "B"])

        self.assertIn("R", res.per_channel_entropy)
        self.assertEqual(res.per_channel_entropy["R"], 0.0)
        self.assertAlmostEqual(res.per_channel_entropy["G"], 1.0, places=3)
        self.assertGreater(res.per_channel_entropy["B"], 6.0)
        self.assertIsNotNone(res.observation)

    def test_analyze_entropy_rgba_alpha_exclusion(self):
        """Test analyze_entropy for RGBA image where only R, G, B channels are passed."""
        img = np.zeros((10, 10, 4), dtype=np.uint8)
        res = analyze_entropy(img[:, :, :3], ["R", "G", "B"])
        self.assertEqual(list(res.per_channel_entropy.keys()), ["R", "G", "B"])


if __name__ == "__main__":
    unittest.main()
