"""
Unit tests for Histogram & Intensity Analysis module (crypta.steganalysis.histogram).
"""

import unittest
import numpy as np
from crypta.steganalysis.histogram import analyze_histogram


class TestHistogramAnalysis(unittest.TestCase):
    """Test cases for histogram statistics and intensity distributions."""

    def test_constant_image_histogram_stats(self):
        """Constant image has min==max==mean==median and std_dev==0."""
        img = np.full((10, 10, 1), fill_value=128, dtype=np.uint8)
        res = analyze_histogram(img, ["R"])

        r_stats = res.channel_stats["R"]
        self.assertEqual(r_stats["min"], 128.0)
        self.assertEqual(r_stats["max"], 128.0)
        self.assertEqual(r_stats["mean"], 128.0)
        self.assertEqual(r_stats["median"], 128.0)
        self.assertEqual(r_stats["std_dev"], 0.0)

    def test_gradient_image_histogram_stats(self):
        """Gradient array [0..255] has known min=0, max=255, mean~127.5."""
        arr = np.arange(256, dtype=np.uint8).reshape((16, 16, 1))
        res = analyze_histogram(arr, ["R"])

        r_stats = res.channel_stats["R"]
        self.assertEqual(r_stats["min"], 0.0)
        self.assertEqual(r_stats["max"], 255.0)
        self.assertAlmostEqual(r_stats["mean"], 127.5, places=1)
        self.assertAlmostEqual(r_stats["median"], 127.5, places=1)
        self.assertGreater(r_stats["std_dev"], 70.0)

    def test_equalized_adjacent_pair_ratio(self):
        """Equal frequency adjacent pairs have adjacent_pair_ratio near 0.0."""
        # 100 counts of 0 and 100 counts of 1
        arr = np.array([0] * 100 + [1] * 100, dtype=np.uint8).reshape((10, 20, 1))
        res = analyze_histogram(arr, ["R"])

        self.assertEqual(res.adjacent_pair_ratios["R"], 0.0)

    def test_empty_image_histogram_stats(self):
        """Empty image handles stats gracefully."""
        img = np.zeros((0, 0, 1), dtype=np.uint8)
        res = analyze_histogram(img, ["R"])

        r_stats = res.channel_stats["R"]
        self.assertEqual(r_stats["min"], 0.0)
        self.assertEqual(r_stats["max"], 0.0)


if __name__ == "__main__":
    unittest.main()
