"""
High-Level Report Orchestration Engine for Crypta.
Coordinates forensic analysis, steganalysis, and risk assessment to produce HTML and JSON report files.
"""

import time
from pathlib import Path
from typing import Union, Optional, Dict
from crypta.steganography.validators import validate_carrier_image
from crypta.forensics.analyzer import analyze_forensics
from crypta.steganalysis.analyzer import analyze_image
from crypta.reporting.results import CryptaReport
from crypta.reporting.json_report import generate_json_report
from crypta.reporting.html_report import generate_html_report


def resolve_report_path(
    base_dir: Path,
    stem: str,
    extension: str,
    overwrite: bool = False,
) -> Path:
    """Resolve a unique output report file path, avoiding accidental overwrites unless overwrite=True."""
    filename = f"{stem}_crypta_report{extension}"
    target_path = base_dir / filename

    if not overwrite and target_path.exists():
        timestamp = int(time.time())
        filename = f"{stem}_crypta_report_{timestamp}{extension}"
        target_path = base_dir / filename

    return target_path


def build_report(
    image_path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    format_choice: str = "both",
    overwrite: bool = False,
) -> Dict[str, Path]:
    """Execute complete analysis pipeline and generate report files.

    Args:
        image_path: Path to target PNG carrier image.
        output_dir: Directory where report files should be saved (default: 'reports/').
        format_choice: Report format choice ('html', 'json', or 'both').
        overwrite: If True, overwrite existing report files.

    Returns:
        Dict[str, Path]: Dictionary mapping format ('html', 'json') to generated file Path objects.

    Raises:
        FileNotFoundError: If target image file does not exist.
        ValueError: If file is not a valid carrier or format_choice is invalid.
    """
    carrier = validate_carrier_image(image_path)
    fmt = format_choice.lower().strip()
    if fmt == "all":
        fmt = "both"
    if fmt not in ("html", "json", "both"):
        raise ValueError(f"Invalid report format '{format_choice}'. Expected 'html', 'json', or 'both'.")


    # 1. Run Forensic Evidence Collection
    forensic_res = analyze_forensics(carrier.path)

    # 2. Run Steganalysis & Risk Assessment
    analysis_res = analyze_image(carrier.path)

    # 3. Build Unified Report Data Model
    report_data = CryptaReport.from_results(
        forensic_result=forensic_res,
        analysis_result=analysis_res,
    )

    # 4. Resolve Output Directory & Paths
    if output_dir:
        out_dir = Path(output_dir).resolve()
    else:
        out_dir = Path("reports").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = carrier.path.stem
    generated_files: Dict[str, Path] = {}

    # 5. Generate Requested Report Formats
    if fmt in ("html", "both"):
        html_path = resolve_report_path(out_dir, stem, ".html", overwrite=overwrite)
        generated_files["html"] = generate_html_report(report_data, html_path)

    if fmt in ("json", "both"):
        json_path = resolve_report_path(out_dir, stem, ".json", overwrite=overwrite)
        generated_files["json"] = generate_json_report(report_data, json_path)

    return generated_files
