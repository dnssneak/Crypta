"""
Unit Tests for Evidence & Explanation Assessment Engine (Feature 8).
"""

import json
import unittest
from crypta.steganalysis.assessment import (
    generate_observations,
    generate_assessment_summary,
    get_severity_label,
)
from crypta.steganalysis.results import RiskAssessment


class TestAssessmentEngine(unittest.TestCase):
    """Test observation generation, severity labels, and assessment summaries."""

    def test_severity_labels(self):
        self.assertEqual(get_severity_label(10), "Minimal")
        self.assertEqual(get_severity_label(25), "Slight")
        self.assertEqual(get_severity_label(50), "Moderate")
        self.assertEqual(get_severity_label(70), "Elevated")
        self.assertEqual(get_severity_label(90), "Strong")

    def test_generate_observations_low(self):
        scores = {
            "entropy": 10.0,
            "lsb": 5.0,
            "chi_square": 0.0,
            "histogram": 12.0,
            "pixel_statistics": 8.0,
        }
        obs = generate_observations(scores)
        self.assertTrue(len(obs) >= 5)
        self.assertIn("normal", obs[0].lower())

    def test_generate_observations_high(self):
        scores = {
            "entropy": 85.0,
            "lsb": 90.0,
            "chi_square": 95.0,
            "histogram": 80.0,
            "pixel_statistics": 85.0,
        }
        obs = generate_observations(scores)
        self.assertTrue(any("[!]" in o for o in obs))

    def test_disclaimer_presence(self):
        summary = generate_assessment_summary(75, "HIGH", ["Observation 1"])
        self.assertIn("[!]", summary)
        self.assertIn("heuristic", summary.lower())
        self.assertIn("does not confirm", summary.lower())

    def test_risk_assessment_serializable(self):
        ra = RiskAssessment(
            score=75,
            level="HIGH",
            indicator_scores={"lsb": 80.0, "chi_square": 70.0},
            weights={"lsb": 0.3, "chi_square": 0.3},
            observations=["Obs 1"],
            assessment="Test assessment string",
        )
        d = ra.to_dict()
        serialized = json.dumps(d)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["score"], 75)
        self.assertEqual(deserialized["level"], "HIGH")


if __name__ == "__main__":
    unittest.main()
