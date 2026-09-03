"""
Integration Tests for Crypta High-Level Reporting Pipeline (Feature 9).
"""

import tempfile
import unittest
from pathlib import Path
import numpy as np
from PIL import Image

from crypta.reporting.report_generator import build_report, resolve_report_path
from crypta.core.pipeline import hide_file


class TestReportingIntegration(unittest.TestCase):
    """Test build_report pipeline end-to-end for clean and stego images."""

    def test_build_report_both_formats(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "cover_img.png"
            reports_dir = Path(tmp_dir) / "output_reports"

            arr = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            results = build_report(
                image_path=img_path,
                output_dir=reports_dir,
                format_choice="both",
            )

            self.assertIn("html", results)
            self.assertIn("json", results)
            self.assertTrue(results["html"].exists())
            self.assertTrue(results["json"].exists())
            self.assertEqual(results["html"].suffix, ".html")
            self.assertEqual(results["json"].suffix, ".json")

    def test_build_report_format_selection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = Path(tmp_dir) / "cover_img.png"
            reports_dir = Path(tmp_dir) / "output_reports"

            arr = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
            Image.fromarray(arr).save(img_path)

            res_html = build_report(img_path, output_dir=reports_dir, format_choice="html")
            self.assertIn("html", res_html)
            self.assertNotIn("json", res_html)

            res_json = build_report(img_path, output_dir=reports_dir, format_choice="json")
            self.assertNotIn("html", res_json)
            self.assertIn("json", res_json)

    def test_build_report_stego_image(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cover_png = Path(tmp_dir) / "cover.png"
            stego_png = Path(tmp_dir) / "stego.png"
            secret_txt = Path(tmp_dir) / "secret.txt"
            reports_dir = Path(tmp_dir) / "reports"

            arr = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
            Image.fromarray(arr).save(cover_png)
            secret_txt.write_bytes(b"Crypta Secret Report Data " * 50)

            hide_file(
                carrier_path=cover_png,
                secret_path=secret_txt,
                output_path=stego_png,
                password="TestReportPassword123!",
                overwrite=True,
            )

            results = build_report(
                image_path=stego_png,
                output_dir=reports_dir,
                format_choice="both",
            )

            self.assertTrue(results["html"].exists())
            self.assertTrue(results["json"].exists())

    def test_resolve_report_path_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = Path(tmp_dir)
            p1 = resolve_report_path(base_dir, "test", ".html", overwrite=False)
            p1.write_text("existing", encoding="utf-8")

            # Resolving again without overwrite must yield a different path with timestamp
            p2 = resolve_report_path(base_dir, "test", ".html", overwrite=False)
            self.assertNotEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()
