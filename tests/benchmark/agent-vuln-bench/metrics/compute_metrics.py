"""
Metrics Computation Engine for Agent-Vuln-Bench.

Calculates aggregate metrics from evaluation results including:
- Core metrics: Recall, Precision, F1, FPR
- Per-Set breakdown: Set A/B/C Recall
- Taint analysis depth
- Per-dataset breakdown
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Import from harness when used as module
try:
    from ..harness.oracle_eval import EvalResult
except ImportError:
    # Fallback for standalone use
    from dataclasses import dataclass

    @dataclass
    class EvalResult:
        sample_id: str = ""
        tool_name: str = ""
        true_positives: list = None
        false_negatives: list = None
        false_positives: list = None
        taint_correct: int = 0
        taint_partial: int = 0
        taint_missed: int = 0
        set_a_tp: int = 0
        set_a_total: int = 0
        set_b_tp: int = 0
        set_b_total: int = 0
        set_c_tp: int = 0
        set_c_total: int = 0
        scan_time: float = 0.0


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safe division that returns default if denominator is 0."""
    return numerator / denominator if denominator > 0 else default


def compute_aggregate_metrics(results: List[EvalResult]) -> Dict[str, Any]:
    """
    Compute aggregate metrics from multiple sample evaluation results.

    Args:
        results: List of EvalResult from evaluating samples.

    Returns:
        Dictionary containing all aggregate metrics.
    """
    if not results:
        return {
            "total_samples": 0,
            "recall": 0.0,
            "precision": 0.0,
            "f1": 0.0,
            "fpr": 0.0,
        }

    # Core counts
    total_tp = sum(len(r.true_positives) if r.true_positives else 0 for r in results)
    total_fn = sum(len(r.false_negatives) if r.false_negatives else 0 for r in results)
    total_fp = sum(len(r.false_positives) if r.false_positives else 0 for r in results)
    total_tn = 0  # Not always available

    # Core metrics
    total_vulns = total_tp + total_fn
    recall = safe_div(total_tp, total_vulns)
    precision = safe_div(total_tp, total_tp + total_fp)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(total_fp, total_fp + total_tp)

    # Per-Set metrics
    set_a_tp = sum(r.set_a_tp for r in results)
    set_a_total = sum(r.set_a_total for r in results)
    set_b_tp = sum(r.set_b_tp for r in results)
    set_b_total = sum(r.set_b_total for r in results)
    set_c_tp = sum(r.set_c_tp for r in results)
    set_c_total = sum(r.set_c_total for r in results)

    set_a_recall = safe_div(set_a_tp, set_a_total)
    set_b_recall = safe_div(set_b_tp, set_b_total)
    set_c_recall = safe_div(set_c_tp, set_c_total)

    # Per-Set F1 (assumes FP distribution is unknown per-set)
    # Simplified: use recall as proxy since we don't track per-set FP
    set_a_f1 = set_a_recall  # Simplified
    set_b_f1 = set_b_recall
    set_c_f1 = set_c_recall

    # Taint depth metrics (P3)
    taint_correct = sum(r.taint_correct for r in results)
    taint_partial = sum(r.taint_partial for r in results)
    taint_missed = sum(r.taint_missed for r in results)
    taint_total = taint_correct + taint_partial + taint_missed

    taint_accuracy = safe_div(taint_correct, taint_total)
    taint_coverage = safe_div(taint_correct + taint_partial, taint_total)

    # Timing
    total_scan_time = sum(r.scan_time for r in results)
    avg_scan_time = safe_div(total_scan_time, len(results))

    return {
        # Core metrics
        "total_samples": len(results),
        "total_vulns": total_vulns,
        "total_tp": total_tp,
        "total_fn": total_fn,
        "total_fp": total_fp,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        # Per-Set (P2)
        "set_a_recall": round(set_a_recall, 4),
        "set_a_total": set_a_total,
        "set_a_tp": set_a_tp,
        "set_a_f1": round(set_a_f1, 4),
        "set_b_recall": round(set_b_recall, 4),
        "set_b_total": set_b_total,
        "set_b_tp": set_b_tp,
        "set_b_f1": round(set_b_f1, 4),
        "set_c_recall": round(set_c_recall, 4),
        "set_c_total": set_c_total,
        "set_c_tp": set_c_tp,
        "set_c_f1": round(set_c_f1, 4),
        # Taint depth (P3)
        "taint_accuracy": round(taint_accuracy, 4),
        "taint_coverage": round(taint_coverage, 4),
        "taint_correct": taint_correct,
        "taint_partial": taint_partial,
        "taint_missed": taint_missed,
        "taint_total": taint_total,
        # Timing
        "total_scan_time": round(total_scan_time, 2),
        "avg_scan_time": round(avg_scan_time, 2),
    }


def compute_metrics_enhanced(results: List[EvalResult]) -> Dict[str, Any]:
    """
    Enhanced metrics for CI: overall + set_A/set_B/set_C as nested dicts
    for quality_gate_check compatibility.
    """
    base = compute_aggregate_metrics(results)
    return {
        "overall": {
            "recall": base.get("recall", 0),
            "precision": base.get("precision", 0),
            "f1": base.get("f1", 0),
            "fpr": base.get("fpr", 0),
            "total_tp": base.get("total_tp", 0),
            "total_fn": base.get("total_fn", 0),
            "total_fp": base.get("total_fp", 0),
        },
        "set_A": {
            "recall": base.get("set_a_recall", 0),
            "precision": base.get("set_a_recall", 0),  # proxy
            "sample_count": base.get("set_a_total", 0),
        },
        "set_B": {
            "recall": base.get("set_b_recall", 0),
            "precision": base.get("set_b_recall", 0),
            "sample_count": base.get("set_b_total", 0),
        },
        "set_C": {
            "recall": base.get("set_c_recall", 0),
            "precision": base.get("set_c_recall", 0),
            "sample_count": base.get("set_c_total", 0),
        },
        **{k: v for k, v in base.items() if k not in ("recall", "precision", "f1", "fpr",
            "set_a_recall", "set_a_total", "set_a_tp", "set_a_f1",
            "set_b_recall", "set_b_total", "set_b_tp", "set_b_f1",
            "set_c_recall", "set_c_total", "set_c_tp", "set_c_f1")},
    }


def compute_dataset_breakdown(
    results: List[EvalResult],
    sample_types: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    """
    Compute metrics broken down by dataset type.

    Args:
        results: List of EvalResult.
        sample_types: Mapping of sample_id to dataset type ('knowns', 'wilds', 'noise').

    Returns:
        Dictionary with metrics for each dataset type.
    """
    by_type: Dict[str, List[EvalResult]] = {"knowns": [], "wilds": [], "noise": []}

    for result in results:
        dtype = sample_types.get(result.sample_id, "unknown")
        if dtype in by_type:
            by_type[dtype].append(result)

    return {dtype: compute_aggregate_metrics(type_results) for dtype, type_results in by_type.items()}


def compute_severity_breakdown(
    results: List[EvalResult],
) -> Dict[str, Dict[str, int]]:
    """
    Compute TP/FN breakdown by severity.

    Args:
        results: List of EvalResult.

    Returns:
        Dictionary with counts per severity level.
    """
    severities = {"CRITICAL": {"tp": 0, "fn": 0}, "HIGH": {"tp": 0, "fn": 0}, "MEDIUM": {"tp": 0, "fn": 0}, "LOW": {"tp": 0, "fn": 0}}

    for result in results:
        # Count TPs by severity
        if result.true_positives:
            for tp in result.true_positives:
                oracle = tp.oracle_entry if hasattr(tp, "oracle_entry") else tp.get("oracle_entry", {})
                sev = oracle.get("severity", "MEDIUM") if isinstance(oracle, dict) else "MEDIUM"
                if sev in severities:
                    severities[sev]["tp"] += 1

        # Count FNs by severity
        if result.false_negatives:
            for fn in result.false_negatives:
                sev = fn.get("severity", "MEDIUM") if isinstance(fn, dict) else "MEDIUM"
                if sev in severities:
                    severities[sev]["fn"] += 1

    return severities
