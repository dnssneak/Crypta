"""
Unit Tests for Crypta HTML Report Generator (Feature 9).
Includes XSS injection protection tests and HTML layout checks.
"""

import tempfile
import unittest
from pathlib import Path
import numpy as np
from PIL import Image

from crypta.forensics.analyzer import analyze_forensics
from crypta.steganalysis.analyzer import analyze_image
from crypta.reporting.results import CryptaReport
from crypta.reporting.html_report import generate_html_report


class TestHTMLReportGenerator(unittest.TestCase):
    """Test HTML report generation and XSS security escaping."""

    def test_generate_html_report_basic(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "sample_image.png"
            html_out = Path(tmp_dir) / "sample_report.html"

            arr = np.random.randint(0, 256, (40, 40, 3), dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            forensic_res = analyze_forensics(img_path)
            analysis_res = analyze_image(img_path)
            report = CryptaReport.from_results(forensic_res, analysis_res)

            res_path = generate_html_report(report, html_out)

            self.assertTrue(res_path.exists())
            html_content = res_path.read_text(encoding="utf-8")

            self.assertIn("CRYPTA ANALYSIS REPORT", html_content)
            self.assertIn("sample_image.png", html_content)
            self.assertIn("Steganography Risk Assessment", html_content)
            self.assertIn("This assessment is a heuristic statistical evaluation", html_content)

    def test_xss_protection(self):
        """Verify malicious metadata strings with <script> tags are strictly HTML-escaped."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "test.png"
            html_out = Path(tmp_dir) / "test_report.html"

            arr = np.zeros((30, 30, 3), dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            forensic_res = analyze_forensics(img_path)
            analysis_res = analyze_image(img_path)
            report = CryptaReport.from_results(forensic_res, analysis_res)

            # Inject malicious script into filename and observation
            report.target["filename"] = "<script>alert('XSS_TARGET')</script>"
            report.risk_assessment["observations"] = ["<script>alert('XSS_OBS')</script>"]
            report.risk_assessment["assessment"] = "Safe <script>alert('XSS_ASSESS')</script>"

            res_path = generate_html_report(report, html_out)
            html_content = res_path.read_text(encoding="utf-8")

            # Must NOT contain raw unescaped script tags
            self.assertNotIn("<script>alert('XSS_TARGET')</script>", html_content)
            self.assertNotIn("<script>alert('XSS_OBS')</script>", html_content)
            self.assertNotIn("<script>alert('XSS_ASSESS')</script>", html_content)

            # Must contain escaped entities
            self.assertIn("&lt;script&gt;alert(&#x27;XSS_TARGET&#x27;)&lt;/script&gt;", html_content)


if __name__ == "__main__":
    unittest.main()
