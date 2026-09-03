"""
Structured Report Result objects for Crypta Reporting Engine.
Provides strongly-typed dataclass container aggregating forensics, steganalysis, and risk assessment into a single serializable object.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from crypta.utils.constants import APPLICATION_NAME, VERSION
from crypta.forensics.results import ForensicResult
from crypta.steganalysis.results import AnalysisResult, RiskAssessment


@dataclass
class CryptaReport:
    """Master container aggregating all analysis results into a single report data model."""

    report_metadata: Dict[str, Any]
    target: Dict[str, Any]
    forensics: Dict[str, Any]
    steganalysis: Dict[str, Any]
    risk_assessment: Dict[str, Any]

    @classmethod
    def from_results(
        cls,
        forensic_result: ForensicResult,
        analysis_result: AnalysisResult,
        risk_assessment: Optional[RiskAssessment] = None,
    ) -> "CryptaReport":
        """Factory method building a CryptaReport instance from domain result objects."""
        risk_obj = risk_assessment or analysis_result.risk_assessment
        now_str = datetime.now(timezone.utc).isoformat()

        report_meta = {
            "tool": APPLICATION_NAME,
            "version": VERSION,
            "report_version": "1.0",
            "generated_at": now_str,
        }

        target_info = {
            "filename": forensic_result.file.file_name,
            "file_path": str(forensic_result.file.file_path),
            "format": forensic_result.format.detected_format,
            "sha256": forensic_result.file.sha256_hash,
            "size_bytes": forensic_result.file.size_bytes,
            "size_human": forensic_result.file.size_human,
        }

        return cls(
            report_metadata=report_meta,
            target=target_info,
            forensics=forensic_result.to_dict(),
            steganalysis=analysis_result.to_dict(),
            risk_assessment=risk_obj.to_dict() if risk_obj else {},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert full report into a JSON-serializable dictionary."""
        return {
            "report_metadata": self.report_metadata,
            "target": self.target,
            "forensics": self.forensics,
            "steganalysis": self.steganalysis,
            "risk_assessment": self.risk_assessment,
        }
