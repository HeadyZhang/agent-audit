"""
Oracle Evaluation Engine for Agent-Vuln-Bench.

Compares tool findings against ground truth oracle to compute
true positives, false negatives, false positives, and taint accuracy.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from .adapters.base_adapter import ToolFinding


@dataclass
class MatchedFinding:
    """A finding matched to an oracle entry."""

    oracle_entry: Dict[str, Any]
    tool_finding: ToolFinding
    taint_verified: bool = False


@dataclass
class EvalResult:
    """Result of evaluating a single sample."""

    sample_id: str
    tool_name: str

    # Core metrics
    true_positives: List[MatchedFinding] = field(default_factory=list)
    false_negatives: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[ToolFinding] = field(default_factory=list)
    true_negatives: List[Dict[str, Any]] = field(default_factory=list)

    # Taint analysis depth (P3)
    taint_correct: int = 0
    taint_partial: int = 0
    taint_missed: int = 0

    # Set breakdown
    set_a_tp: int = 0
    set_a_total: int = 0
    set_b_tp: int = 0
    set_b_total: int = 0
    set_c_tp: int = 0
    set_c_total: int = 0

    # Timing
    scan_time: float = 0.0

    # Unclassified findings (not in oracle, for noise tracking)
    unclassified_findings: List[ToolFinding] = field(default_factory=list)

    @property
    def recall(self) -> float:
        """Calculate recall for this sample."""
        total = len(self.true_positives) + len(self.false_negatives)
        if total == 0:
            return 1.0
        return len(self.true_positives) / total

    @property
    def precision(self) -> float:
        """Calculate precision for this sample."""
        total = len(self.true_positives) + len(self.false_positives)
        if total == 0:
            return 1.0
        return len(self.true_positives) / total


def load_oracle(sample_dir: str) -> Dict[str, Any]:
    """
    Load oracle.yaml from a sample directory.

    Args:
        sample_dir: Path to the sample directory.

    Returns:
        Parsed oracle dictionary.
    """
    oracle_path = Path(sample_dir) / "oracle.yaml"
    if not oracle_path.exists():
        return {"vulnerabilities": [], "safe_patterns": []}

    with open(oracle_path) as f:
        return yaml.safe_load(f) or {}


def find_matching_finding(
    oracle_entry: Dict[str, Any],
    findings: List[ToolFinding],
    matched_ids: Set[int],
    line_tolerance: int = 5,
) -> Optional[ToolFinding]:
    """
    Find a tool finding that matches an oracle entry.

    Args:
        oracle_entry: Oracle vulnerability or safe pattern entry.
        findings: List of tool findings to search.
        matched_ids: Set of finding IDs already matched (to avoid double-matching).
        line_tolerance: Acceptable line number difference.

    Returns:
        Matching ToolFinding or None.
    """
    oracle_file = oracle_entry.get("file", "")
    oracle_line = oracle_entry.get("line", 0)

    # Handle line_range for fuzzy matching
    if "line_range" in oracle_entry:
        line_range = oracle_entry["line_range"]
        oracle_line = (line_range[0] + line_range[1]) // 2
        line_tolerance = max(line_tolerance, (line_range[1] - line_range[0]) // 2 + 5)

    for finding in findings:
        if id(finding) in matched_ids:
            continue

        if finding.matches_oracle(oracle_file, oracle_line, line_tolerance):
            return finding

    return None


def validates_taint_flow(
    finding: ToolFinding,
    oracle_taint: Dict[str, Any],
) -> bool:
    """
    Verify if the tool correctly identified the taint flow.

    P3: Deep analysis - does the tool understand source->sink?

    Args:
        finding: The tool finding.
        oracle_taint: The expected taint flow from oracle.

    Returns:
        True if taint flow is correctly identified.

    Note:
        agent-audit v0.4.x does not output taint information,
        so this will always return False for current version.
        This is intentional - it highlights the gap that benchmark
        aims to measure and drive improvement.
    """
    # Check if finding has taint information
    tool_specific = finding.tool_specific

    # agent-audit v0.4.x doesn't provide taint output
    # Future versions should include source/sink in output
    if not tool_specific:
        return False

    # Check for taint-related fields (for future versions)
    if "taint_source" in tool_specific or "source" in tool_specific:
        oracle_source_type = oracle_taint.get("source", {}).get("type", "")
        oracle_sink_type = oracle_taint.get("sink", {}).get("type", "")

        tool_source = tool_specific.get("taint_source", tool_specific.get("source", ""))
        tool_sink = tool_specific.get("taint_sink", tool_specific.get("sink", ""))

        # Partial match on types
        if oracle_source_type in str(tool_source) and oracle_sink_type in str(tool_sink):
            return True

    return False


def evaluate_taint_overlap(
    finding: ToolFinding,
    oracle_taint: Dict[str, Any],
    line_tolerance: int = 5,
) -> float:
    """
    Evaluate taint chain overlap (0.0–1.0).

    Returns: source match +0.33, sink match +0.34, propagation overlap +0.33.
    """
    score = 0.0
    if not oracle_taint:
        return 0.0

    def location_match(f: ToolFinding, loc: Dict[str, Any]) -> bool:
        if not loc:
            return False
        loc_file = loc.get("location", "").split(":")[0] or loc.get("file", "")
        loc_line = loc.get("line", 0)
        if isinstance(loc.get("location"), str) and ":" in str(loc.get("location", "")):
            parts = str(loc["location"]).split(":")
            loc_file = parts[0]
            loc_line = int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0
        if loc_file and not f.file.endswith(loc_file.replace(":", "")):
            return False
        return abs(f.line - (loc_line or 0)) <= line_tolerance

    source = oracle_taint.get("source", {})
    sink = oracle_taint.get("sink", {})
    if source and (finding.file.endswith(str(source.get("file", "")).split(":")[0]) and
                   abs(finding.line - source.get("line", finding.line)) <= line_tolerance):
        score += 0.33
    if sink and (finding.file.endswith(str(sink.get("file", "")).split(":")[0]) and
                 abs(finding.line - sink.get("line", finding.line)) <= line_tolerance):
        score += 0.34
    for step in oracle_taint.get("propagation", []):
        loc = step if isinstance(step, dict) else {}
        if location_match(finding, loc):
            score += 0.33
            break
    return min(1.0, score)


def evaluate_finding_enhanced(
    finding: ToolFinding,
    oracle_vuln: Dict[str, Any],
    base_match: bool,
) -> Dict[str, Any]:
    """
    Enhanced match evaluation: confidence and tier checks.

    Returns dict with confidence, tier, confidence_reasonable (for TP).
    """
    details = {"match": base_match}
    if getattr(finding, "confidence", None) is not None:
        details["confidence"] = finding.confidence
        details["tier"] = getattr(finding, "tier", "UNKNOWN")
        if base_match:
            details["confidence_reasonable"] = finding.confidence >= 0.60
    return details


def evaluate_sample(
    sample_dir: str,
    tool_findings: List[ToolFinding],
    tool_name: str,
) -> EvalResult:
    """
    Evaluate tool findings against oracle ground truth.

    Args:
        sample_dir: Path to the sample directory containing oracle.yaml.
        tool_findings: List of findings from the tool.
        tool_name: Name of the tool being evaluated.

    Returns:
        EvalResult with all metrics.
    """
    oracle = load_oracle(sample_dir)
    metadata = oracle.get("metadata", {})
    taxonomy = oracle.get("taxonomy", {})

    result = EvalResult(
        sample_id=metadata.get("sample_id", Path(sample_dir).name),
        tool_name=tool_name,
    )

    vulnerabilities = oracle.get("vulnerabilities", [])
    safe_patterns = oracle.get("safe_patterns", [])

    matched_finding_ids: Set[int] = set()

    # --- Step 1: Check each oracle vulnerability ---
    for vuln in vulnerabilities:
        vuln_set = vuln.get("taxonomy_override", {}).get("set_class", taxonomy.get("set_class", ""))

        # Track set totals
        if vuln_set == "A":
            result.set_a_total += 1
        elif vuln_set == "B":
            result.set_b_total += 1
        elif vuln_set == "C":
            result.set_c_total += 1

        # Find matching finding
        matched = find_matching_finding(vuln, tool_findings, matched_finding_ids)

        if matched:
            matched_finding_ids.add(id(matched))

            # Check taint accuracy
            taint_info = vuln.get("taint")
            taint_verified = False
            if taint_info:
                taint_verified = validates_taint_flow(matched, taint_info)
                if taint_verified:
                    result.taint_correct += 1
                else:
                    result.taint_partial += 1

            result.true_positives.append(
                MatchedFinding(
                    oracle_entry=vuln,
                    tool_finding=matched,
                    taint_verified=taint_verified,
                )
            )

            # Track set TP
            if vuln_set == "A":
                result.set_a_tp += 1
            elif vuln_set == "B":
                result.set_b_tp += 1
            elif vuln_set == "C":
                result.set_c_tp += 1
        else:
            result.false_negatives.append(vuln)
            if vuln.get("taint"):
                result.taint_missed += 1

    # --- Step 2: Check safe patterns for FPs ---
    for safe in safe_patterns:
        matched = find_matching_finding(safe, tool_findings, matched_finding_ids)
        if matched:
            # Tool reported a safe pattern as finding = FP
            matched_finding_ids.add(id(matched))
            result.false_positives.append(matched)
        else:
            result.true_negatives.append(safe)

    # --- Step 3: Remaining findings are unclassified ---
    for finding in tool_findings:
        if id(finding) not in matched_finding_ids:
            # For noise datasets, these contribute to noise count
            # For knowns/wilds, these are potential FPs not in oracle
            result.unclassified_findings.append(finding)

    return result


def evaluate_all_samples(
    samples: List[Dict[str, Any]],
    tool_findings_by_sample: Dict[str, List[ToolFinding]],
    tool_name: str,
) -> List[EvalResult]:
    """
    Evaluate multiple samples.

    Args:
        samples: List of sample configs with 'id' and 'dir' keys.
        tool_findings_by_sample: Findings keyed by sample ID.
        tool_name: Name of the tool.

    Returns:
        List of EvalResult for each sample.
    """
    results = []
    for sample in samples:
        sample_id = sample.get("id", "")
        sample_dir = sample.get("dir", "")
        findings = tool_findings_by_sample.get(sample_id, [])
        result = evaluate_sample(sample_dir, findings, tool_name)
        results.append(result)
    return results
