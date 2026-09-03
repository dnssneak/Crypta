"""
Unit tests for LSB Distribution Analysis module (crypta.steganalysis.lsb_analysis).
"""

import unittest
import numpy as np
from crypta.steganalysis.lsb_analysis import analyze_lsb


class TestLSBAnalysis(unittest.TestCase):
    """Test cases for LSB 0/1 distribution and deviation analysis."""

    def test_exact_lsb_counts(self):
        """Test exact LSB bit count calculations on deterministic array."""
        # Pixels: 0 (LSB 0), 1 (LSB 1), 2 (LSB 0), 3 (LSB 1)
        img = np.array([[[0], [1]], [[2], [3]]], dtype=np.uint8) # 2x2x1
        res = analyze_lsb(img, ["R"])

        self.assertEqual(res.zero_counts["R"], 2)
        self.assertEqual(res.one_counts["R"], 2)
        self.assertEqual(res.zero_percentages["R"], 50.0)
        self.assertEqual(res.one_percentages["R"], 50.0)
        self.assertEqual(res.deviations["R"], 0.0)

    def test_biased_lsb_distribution(self):
        """Test 100% 0-bit biased LSB distribution."""
        # All even numbers -> LSB is 0
        img = np.array([[[0], [2]], [[4], [6]]], dtype=np.uint8)
        res = analyze_lsb(img, ["R"])

        self.assertEqual(res.zero_counts["R"], 4)
        self.assertEqual(res.one_counts["R"], 0)
        self.assertEqual(res.zero_percentages["R"], 100.0)
        self.assertEqual(res.one_percentages["R"], 0.0)
        self.assertEqual(res.deviations["R"], 50.0)

    def test_multi_channel_rgb_analysis(self):
        """Test LSB analysis across multiple channels (RGB)."""
        img = np.zeros((10, 10, 3), dtype=np.uint8)
        img[:, :, 0] = 0  # R: all LSB 0
        img[:, :, 1] = 1  # G: all LSB 1
        # B: alternating 0 and 1
        img[:5, :, 2] = 0
        img[5:, :, 2] = 1

        res = analyze_lsb(img, ["R", "G", "B"])

        self.assertEqual(res.zero_percentages["R"], 100.0)
        self.assertEqual(res.one_percentages["G"], 100.0)
        self.assertEqual(res.deviations["B"], 0.0)
        self.assertIn("R", res.zero_counts)
        self.assertIn("G", res.zero_counts)
        self.assertIn("B", res.zero_counts)


if __name__ == "__main__":
    unittest.main()
