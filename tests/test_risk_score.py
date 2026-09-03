"""
Unit and Integration Tests for Crypta Steganalysis Risk Scoring Engine (Feature 8).
"""

import math
import unittest
from pathlib import Path
import numpy as np
from PIL import Image

from crypta.utils.constants import (
    RISK_LEVEL_LOW,
    RISK_LEVEL_MODERATE,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_VERY_HIGH,
)
from crypta.steganalysis.results import (
    ImageInfo,
    EntropyResult,
    LSBResult,
    ChiSquareResult,
    HistogramResult,
    PixelStatsResult,
    AnalysisResult,
    RiskAssessment,
)
from crypta.steganalysis.risk_score import (
    clamp,
    normalize_range,
    get_risk_level,
    score_entropy,
    score_lsb,
    score_chi_square,
    score_histogram,
    score_pixel_stats,
    calculate_risk_score,
)
from crypta.steganalysis.analyzer import analyze_image
from crypta.core.pipeline import hide_file


class TestRiskScoreNormalization(unittest.TestCase):
    """Test normalization and clamping helper functions."""

    def test_clamp_normal(self):
        self.assertEqual(clamp(50.0, 0.0, 100.0), 50.0)
        self.assertEqual(clamp(-10.0, 0.0, 100.0), 0.0)
        self.assertEqual(clamp(150.0, 0.0, 100.0), 100.0)

    def test_clamp_nan_and_inf(self):
        self.assertEqual(clamp(float("nan"), 0.0, 100.0), 0.0)
        self.assertEqual(clamp(float("inf"), 0.0, 100.0), 0.0)
        self.assertEqual(clamp(float("-inf"), 0.0, 100.0), 0.0)

    def test_normalize_range(self):
        self.assertAlmostEqual(normalize_range(5.0, 0.0, 10.0), 50.0)
        self.assertAlmostEqual(normalize_range(0.0, 0.0, 10.0), 0.0)
        self.assertAlmostEqual(normalize_range(10.0, 0.0, 10.0), 100.0)
        # Out of bounds
        self.assertAlmostEqual(normalize_range(-5.0, 0.0, 10.0), 0.0)
        self.assertAlmostEqual(normalize_range(15.0, 0.0, 10.0), 100.0)
        # Equal min/max
        self.assertEqual(normalize_range(5.0, 5.0, 5.0), 0.0)


class TestRiskLevelClassification(unittest.TestCase):
    """Test get_risk_level classification boundaries."""

    def test_risk_level_boundaries(self):
        self.assertEqual(get_risk_level(0), RISK_LEVEL_LOW)
        self.assertEqual(get_risk_level(29), RISK_LEVEL_LOW)
        self.assertEqual(get_risk_level(30), RISK_LEVEL_MODERATE)
        self.assertEqual(get_risk_level(59), RISK_LEVEL_MODERATE)
        self.assertEqual(get_risk_level(60), RISK_LEVEL_HIGH)
        self.assertEqual(get_risk_level(79), RISK_LEVEL_HIGH)
        self.assertEqual(get_risk_level(80), RISK_LEVEL_VERY_HIGH)
        self.assertEqual(get_risk_level(100), RISK_LEVEL_VERY_HIGH)

    def test_risk_level_clamping(self):
        self.assertEqual(get_risk_level(-10), RISK_LEVEL_LOW)
        self.assertEqual(get_risk_level(200), RISK_LEVEL_VERY_HIGH)
        self.assertEqual(get_risk_level(float("nan")), RISK_LEVEL_LOW)


class TestSubEngineScoring(unittest.TestCase):
    """Test individual indicator scoring functions."""

    def test_alpha_channel_exclusion(self):
        """Verify Alpha channel 'A' is strictly ignored in all scoring functions."""
        channels = ["R", "G", "B", "A"]

        # LSB
        lsb = LSBResult(
            zero_counts={"R": 50, "G": 50, "B": 50, "A": 0},
            one_counts={"R": 50, "G": 50, "B": 50, "A": 100},
            zero_percentages={"R": 50.0, "G": 50.0, "B": 50.0, "A": 0.0},
            one_percentages={"R": 50.0, "G": 50.0, "B": 50.0, "A": 100.0},
            deviations={"R": 0.0, "G": 0.0, "B": 0.0, "A": 50.0},
            observation="test",
        )
        # If A was included, average score would drop significantly due to A's 50% deviation
        score_with_alpha = score_lsb(lsb, ["R", "G", "B", "A"])
        score_without_alpha = score_lsb(lsb, ["R", "G", "B"])
        self.assertEqual(score_with_alpha, score_without_alpha)
        self.assertEqual(score_with_alpha, 100.0)

    def test_chi_square_scoring(self):
        chi_low_p = ChiSquareResult(
            statistics={"R": 250.0, "G": 200.0, "B": 300.0},
            degrees_of_freedom={"R": 127, "G": 127, "B": 127},
            p_values={"R": 0.0, "G": 0.001, "B": 0.0},
            observation="test",
        )
        score = score_chi_square(chi_low_p, ["R", "G", "B"])
        self.assertGreaterEqual(score, 99.0)

        chi_high_p = ChiSquareResult(
            statistics={"R": 10.0, "G": 12.0, "B": 8.0},
            degrees_of_freedom={"R": 127, "G": 127, "B": 127},
            p_values={"R": 1.0, "G": 1.0, "B": 1.0},
            observation="test",
        )
        score_high = score_chi_square(chi_high_p, ["R", "G", "B"])
        self.assertEqual(score_high, 0.0)


class TestCalculateRiskScore(unittest.TestCase):
    """Test full calculate_risk_score functionality and determinism."""

    def setUp(self):
        self.img_info = ImageInfo(
            file_path=Path("test.png"),
            file_name="test.png",
            format="PNG",
            width=100,
            height=100,
            mode="RGB",
            channels=3,
            file_size_bytes=30000,
            analyzed_channels=["R", "G", "B"],
            alpha_excluded=False,
        )

    def test_deterministic_scoring(self):
        entropy_res = EntropyResult(7.5, {"R": 7.5, "G": 7.5, "B": 7.5}, "obs")
        lsb_res = LSBResult({}, {}, {"R": 50.0}, {"R": 50.0}, {"R": 0.0, "G": 0.0, "B": 0.0}, "obs")
        chi_res = ChiSquareResult({"R": 10.0}, {"R": 127}, {"R": 0.01, "G": 0.01, "B": 0.01}, "obs")
        hist_res = HistogramResult({}, {"R": 1.0, "G": 1.0, "B": 1.0}, "obs")
        pix_res = PixelStatsResult(10000, {}, {}, {}, {}, {}, {"R": 0.50, "G": 0.50, "B": 0.50}, "obs")

        analysis = AnalysisResult(
            image_info=self.img_info,
            entropy=entropy_res,
            lsb_analysis=lsb_res,
            chi_square=chi_res,
            histogram=hist_res,
            pixel_statistics=pix_res,
        )

        res1 = calculate_risk_score(analysis)
        res2 = calculate_risk_score(analysis)

        self.assertEqual(res1.score, res2.score)
        self.assertEqual(res1.level, res2.level)
        self.assertEqual(res1.indicator_scores, res2.indicator_scores)
        self.assertIn("heuristic", res1.assessment.lower())


class TestRealImagesRiskScore(unittest.TestCase):
    """Test risk scoring on generated clean vs stego images using Crypta pipeline."""

    def test_clean_vs_stego_risk_score(self, tmp_path_factory=None):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            clean_png = tmp_path / "clean.png"
            stego_png = tmp_path / "stego.png"
            secret_txt = tmp_path / "secret.txt"

            # Create a 200x200 RGB gradient test image
            arr = np.zeros((200, 200, 3), dtype=np.uint8)
            for i in range(200):
                arr[i, :, 0] = i
                arr[:, i, 1] = (i * 2) % 256
                arr[i, i, 2] = (i * 3) % 256
            Image.fromarray(arr).save(clean_png)

            secret_txt.write_bytes(b"Top Secret Crypta Payload " * 100)

            # Analyze clean image
            clean_res = analyze_image(clean_png)
            self.assertIsNotNone(clean_res.risk_assessment)
            self.assertGreaterEqual(clean_res.risk_assessment.score, 0)
            self.assertLessEqual(clean_res.risk_assessment.score, 100)

            # Embed payload into carrier
            hide_file(
                carrier_path=clean_png,
                secret_path=secret_txt,
                output_path=stego_png,
                password="TestPassword123!",
                overwrite=True,
            )

            # Analyze stego image
            stego_res = analyze_image(stego_png)
            self.assertIsNotNone(stego_res.risk_assessment)
            self.assertGreaterEqual(stego_res.risk_assessment.score, 0)
            self.assertLessEqual(stego_res.risk_assessment.score, 100)

            # Verify risk levels and observations are populated and non-empty
            self.assertIn(clean_res.risk_assessment.level, [RISK_LEVEL_LOW, RISK_LEVEL_MODERATE, RISK_LEVEL_HIGH, RISK_LEVEL_VERY_HIGH])
            self.assertIn(stego_res.risk_assessment.level, [RISK_LEVEL_LOW, RISK_LEVEL_MODERATE, RISK_LEVEL_HIGH, RISK_LEVEL_VERY_HIGH])
            self.assertTrue(len(clean_res.risk_assessment.observations) > 0)
            self.assertTrue(len(stego_res.risk_assessment.observations) > 0)



if __name__ == "__main__":
    unittest.main()
