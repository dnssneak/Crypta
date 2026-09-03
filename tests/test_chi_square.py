"""
Unit tests for Chi-Square Analysis module (crypta.steganalysis.chi_square).
"""

import unittest
import numpy as np
from crypta.steganalysis.chi_square import calculate_chi_square_pov, analyze_chi_square


class TestChiSquareAnalysis(unittest.TestCase):
    """Test cases for Chi-Square PoV statistical analysis."""

    def test_perfectly_equal_povs_yields_zero_chi2(self):
        """When y_2k == y_2k+1 for all pairs, chi-square statistic is 0.0."""
        # 100 pixels of 0 and 100 pixels of 1 -> pair (0, 1) has equal frequency
        arr = np.array([0] * 100 + [1] * 100 + [2] * 50 + [3] * 50, dtype=np.uint8)
        stat, df, p_val = calculate_chi_square_pov(arr)

        self.assertEqual(stat, 0.0)
        self.assertEqual(df, 1) # 2 active pairs (0,1) and (2,3) -> df = 2 - 1 = 1
        self.assertEqual(p_val, 1.0)

    def test_skewed_povs_yields_positive_chi2(self):
        """When y_2k != y_2k+1 significantly across active pairs, chi-square statistic is positive."""
        # 100 pixels of 0 (pair 0) and 50 pixels of 2 (pair 1) -> both pairs have 100% 0-bit
        arr = np.array([0] * 100 + [2] * 50, dtype=np.uint8)
        stat, df, p_val = calculate_chi_square_pov(arr)

        self.assertGreater(stat, 0.0)
        self.assertEqual(df, 1)
        self.assertLess(p_val, 0.05)


    def test_single_value_image_dof(self):
        """Uniform image with only 1 unique pixel value handles DoF safely."""
        arr = np.full(50, 10, dtype=np.uint8) # pair (10, 11) active
        stat, df, p_val = calculate_chi_square_pov(arr)

        self.assertGreaterEqual(stat, 0.0)
        self.assertGreaterEqual(df, 0)
        self.assertIsNotNone(p_val)

    def test_empty_array_chi_square(self):
        """Empty array returns 0.0 safely."""
        arr = np.array([], dtype=np.uint8)
        stat, df, p_val = calculate_chi_square_pov(arr)

        self.assertEqual(stat, 0.0)
        self.assertEqual(df, 0)
        self.assertEqual(p_val, 1.0)

    def test_analyze_chi_square_structured_result(self):
        """Test high-level analyze_chi_square function."""
        img = np.zeros((20, 20, 3), dtype=np.uint8)
        res = analyze_chi_square(img, ["R", "G", "B"])

        self.assertIn("R", res.statistics)
        self.assertIn("G", res.degrees_of_freedom)
        self.assertIn("B", res.p_values)
        self.assertIsNotNone(res.observation)


if __name__ == "__main__":
    unittest.main()
