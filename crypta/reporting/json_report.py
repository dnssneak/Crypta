"""
JSON Report Generator for Crypta Reporting Engine.
Exports structured analysis reports into formatted, human-readable JSON files.
"""

import json
from pathlib import Path
from typing import Union
from crypta.reporting.results import CryptaReport


def generate_json_report(
    report_data: CryptaReport,
    output_path: Union[str, Path],
) -> Path:
    """Generate a formatted JSON report from a CryptaReport object.

    Args:
        report_data: Master CryptaReport data object.
        output_path: Target destination file path.

    Returns:
        Path: Resolved output file path.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    report_dict = report_data.to_dict()

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    return path
