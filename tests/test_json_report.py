"""
Unit Tests for Crypta JSON Report Generator (Feature 9).
"""

import json
import tempfile
import unittest
from pathlib import Path
import numpy as np
from PIL import Image

from crypta.forensics.analyzer import analyze_forensics
from crypta.steganalysis.analyzer import analyze_image
from crypta.reporting.results import CryptaReport
from crypta.reporting.json_report import generate_json_report


class TestJSONReportGenerator(unittest.TestCase):
    """Test JSON report generation and schema compliance."""

    def test_generate_json_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "sample.png"
            json_out = Path(tmp_dir) / "sample_report.json"

            arr = np.random.randint(0, 256, (40, 40, 3), dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            forensic_res = analyze_forensics(img_path)
            analysis_res = analyze_image(img_path)
            report = CryptaReport.from_results(forensic_res, analysis_res)

            res_path = generate_json_report(report, json_out)

            self.assertTrue(res_path.exists())
            with open(res_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["report_metadata"]["tool"], "Crypta")
            self.assertEqual(data["target"]["filename"], "sample.png")
            self.assertIn("score", data["risk_assessment"])


if __name__ == "__main__":
    unittest.main()
