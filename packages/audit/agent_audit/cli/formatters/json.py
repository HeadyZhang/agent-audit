"""JSON output formatter."""

import json
import math
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from agent_audit.models.finding import Finding
from agent_audit.version import __version__


# v0.5.2: Import deduplication from terminal formatter
from agent_audit.cli.formatters.terminal import finalize_findings


def calculate_risk_score(findings: List[Finding]) -> float:
    """
    Calculate confidence-weighted risk score from findings.

    v0.5.2: Uses smoother logarithmic scaling (natural log) to prevent saturation.
    The old formula (2.5 * log2) saturated at ~20 findings. New formula scales
    smoothly up to ~200 findings before approaching 9.8.

    Calibration targets:
    - 0 findings → 0.0
    - 3 WARN findings → ~2.7 (LOW-MEDIUM)
    - 10 WARN findings → ~5.0 (MEDIUM)
    - 20 WARN findings → ~5.8 (MEDIUM)
    - 50 WARN + 5 BLOCK → ~9.3 (HIGH)

    Args:
        findings: List of findings to score

    Returns:
        Risk score from 0.0 to 9.8 (10.0 reserved for theoretical extremes)
    """
    SEVERITY_WEIGHT = {
        "critical": 3.0,
        "high": 1.5,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.1,
    }

    raw = 0.0
    block_count = 0

    for f in findings:
        tier = getattr(f, 'tier', 'WARN')
        if tier not in ('BLOCK', 'WARN') or f.suppressed:
            continue

        weight = SEVERITY_WEIGHT.get(f.severity.value, 0.5)
        raw += f.confidence * weight

        if tier == 'BLOCK':
            block_count += 1

    if raw <= 0:
        return 0.0

    # v0.5.2: Use natural log (ln) with smaller coefficient for smoother scaling
    base_score = 1.8 * math.log(1 + raw)

    # BLOCK (CRITICAL) bonus: +0.3 per BLOCK, capped at 2.0
    block_bonus = min(2.0, block_count * 0.3)

    score = base_score + block_bonus

    # Hard cap at 9.8
    return round(min(9.8, score), 1)


def get_risk_label(score: float) -> str:
    """Get human-readable risk label for a score."""
    if score < 2.0:
        return "LOW"
    elif score < 4.0:
        return "LOW-MEDIUM"
    elif score < 6.0:
        return "MEDIUM"
    elif score < 8.0:
        return "MEDIUM-HIGH"
    else:
        return "HIGH"


class JSONFormatter:
    """JSON output formatter for scan results."""

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def format(
        self,
        findings: List[Finding],
        scan_path: str = "",
        scanned_files: int = 0
    ) -> Dict[str, Any]:
        """
        Format findings as JSON.

        Args:
            findings: List of findings to format
            scan_path: Path that was scanned
            scanned_files: Number of files scanned

        Returns:
            JSON-serializable dictionary
        """
        # v0.5.2: Apply deduplication and post-processing
        findings = finalize_findings(findings)

        return {
            "version": __version__,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "scan_path": scan_path,
            "scanned_files": scanned_files,
            "summary": self._create_summary(findings),
            "findings": [self._finding_to_dict(f) for f in findings],
        }

    def format_to_string(
        self,
        findings: List[Finding],
        scan_path: str = "",
        scanned_files: int = 0
    ) -> str:
        """Format findings as JSON string."""
        data = self.format(findings, scan_path, scanned_files)
        indent = 2 if self.pretty else None
        return json.dumps(data, indent=indent, default=str)

    def save(
        self,
        findings: List[Finding],
        output_path: Path,
        scan_path: str = "",
        scanned_files: int = 0
    ):
        """Save findings as JSON file."""
        json_str = self.format_to_string(findings, scan_path, scanned_files)
        output_path.write_text(json_str, encoding="utf-8")

    def _create_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Create summary statistics."""
        total = len(findings)
        actionable = sum(1 for f in findings if f.is_actionable())
        suppressed_count = sum(1 for f in findings if f.suppressed)

        by_severity: Dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        by_category: Dict[str, int] = {}
        for f in findings:
            cat = f.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        # Count by tier
        by_tier: Dict[str, int] = {"BLOCK": 0, "WARN": 0, "INFO": 0, "SUPPRESSED": 0}
        for f in findings:
            tier = getattr(f, 'tier', 'WARN')
            if tier in by_tier:
                by_tier[tier] += 1
            else:
                by_tier['WARN'] += 1

        risk_score = calculate_risk_score(findings)

        return {
            "total": total,
            "actionable": actionable,
            "suppressed": suppressed_count,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_tier": by_tier,
            "risk_score": risk_score,
            "risk_label": get_risk_label(risk_score),
        }

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary with v0.5.0 fields."""
        base = finding.to_dict()

        # Ensure v0.5.0 fields are present (they should be from to_dict, but ensure)
        if "confidence" not in base:
            base["confidence"] = finding.confidence
        if "tier" not in base:
            base["tier"] = getattr(finding, 'tier', 'WARN')

        # Add reason field (use description as fallback)
        reason = finding.metadata.get("reason") or finding.description
        base["reason"] = reason

        return base


def format_json(
    findings: List[Finding],
    scan_path: str = "",
    scanned_files: int = 0,
    pretty: bool = True
) -> str:
    """Convenience function to format findings as JSON."""
    formatter = JSONFormatter(pretty=pretty)
    return formatter.format_to_string(findings, scan_path, scanned_files)


def save_json(
    findings: List[Finding],
    output_path: Path,
    scan_path: str = "",
    scanned_files: int = 0
):
    """Convenience function to save findings as JSON."""
    formatter = JSONFormatter()
    formatter.save(findings, output_path, scan_path, scanned_files)
