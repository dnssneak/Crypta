"""
Unit Tests for CryptaReport Data Model (Feature 9).
"""

import json
import unittest
from pathlib import Path
from crypta.forensics.analyzer import analyze_forensics
from crypta.steganalysis.analyzer import analyze_image
from crypta.reporting.results import CryptaReport


class TestReportDataModel(unittest.TestCase):
    """Test CryptaReport structure and JSON serializability."""

    def test_crypta_report_from_results(self, tmp_path_factory=None):
        import tempfile
        from PIL import Image
        import numpy as np

        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "test_carrier.png"
            arr = np.full((50, 50, 3), 128, dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            forensic_res = analyze_forensics(img_path)
            analysis_res = analyze_image(img_path)

            report = CryptaReport.from_results(forensic_res, analysis_res)

            self.assertIn("tool", report.report_metadata)
            self.assertEqual(report.report_metadata["tool"], "Crypta")
            self.assertEqual(report.target["filename"], "test_carrier.png")

            d = report.to_dict()
            serialized = json.dumps(d)
            deserialized = json.loads(serialized)

            self.assertEqual(deserialized["target"]["filename"], "test_carrier.png")
            self.assertIn("risk_assessment", deserialized)
            self.assertIn("forensics", deserialized)
            self.assertIn("steganalysis", deserialized)


if __name__ == "__main__":
    unittest.main()
