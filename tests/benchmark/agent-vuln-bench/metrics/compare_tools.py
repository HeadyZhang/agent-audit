"""
Multi-Tool Comparison for Agent-Vuln-Bench.

Generates comparison matrices and reports across multiple SAST tools.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .compute_metrics import compute_aggregate_metrics

# Import from harness when used as module
try:
    from ..harness.oracle_eval import EvalResult
except ImportError:
    EvalResult = Any


def generate_comparison_matrix(
    all_results: Dict[str, List[EvalResult]],
) -> str:
    """
    Generate a Markdown comparison matrix from multiple tools' results.

    Args:
        all_results: Dictionary mapping tool name to list of EvalResult.

    Returns:
        Markdown-formatted comparison matrix.
    """
    if not all_results:
        return "No results to compare."

    # Compute metrics for each tool
    tool_metrics: Dict[str, Dict[str, Any]] = {}
    for tool_name, results in all_results.items():
        tool_metrics[tool_name] = compute_aggregate_metrics(results)

    tools = list(tool_metrics.keys())

    lines = ["## Multi-Tool Comparison Matrix\n"]

    # Helper to highlight best value
    def format_metric(value: float, best: float, higher_is_better: bool = True) -> str:
        formatted = f"{value:.1%}" if isinstance(value, float) and value <= 1 else str(value)
        if higher_is_better:
            is_best = value == best and best > 0
        else:
            is_best = value == best and best < float("inf")
        return f"**{formatted}**" if is_best else formatted

    # Core metrics table
    lines.append("### Core Metrics\n")
    lines.append("| Metric | " + " | ".join(tools) + " |")
    lines.append("|--------|" + "|".join("------" for _ in tools) + "|")

    core_metrics = [
        ("Recall", "recall", True),
        ("Precision", "precision", True),
        ("F1 Score", "f1", True),
        ("FPR", "fpr", False),
    ]

    for label, key, higher_better in core_metrics:
        values = [tool_metrics[t].get(key, 0) for t in tools]
        best = max(values) if higher_better else min(values)
        row = f"| {label} |"
        for v in values:
            row += f" {format_metric(v, best, higher_better)} |"
        lines.append(row)

    # Per-Set breakdown
    lines.append("\n### Per-Set Recall\n")
    lines.append("| Set | " + " | ".join(tools) + " | Note |")
    lines.append("|-----|" + "|".join("------" for _ in tools) + "|------|")

    set_info = [
        ("Set A (Injection & RCE)", "set_a_recall", "agent-audit >> Bandit/Semgrep"),
        ("Set B (MCP & Component)", "set_b_recall", "agent-audit unique advantage"),
        ("Set C (Data & Auth)", "set_c_recall", "Similar across tools"),
    ]

    for label, key, note in set_info:
        values = [tool_metrics[t].get(key, 0) for t in tools]
        best = max(values)
        row = f"| {label} |"
        for v in values:
            row += f" {format_metric(v, best)} |"
        row += f" {note} |"
        lines.append(row)

    # Taint depth
    lines.append("\n### Taint Analysis Depth (P3)\n")
    lines.append("| Tool | Taint Accuracy | Taint Coverage | Status |")
    lines.append("|------|----------------|----------------|--------|")

    for tool in tools:
        m = tool_metrics[tool]
        taint_acc = m.get("taint_accuracy", 0)
        taint_cov = m.get("taint_coverage", 0)
        status = "Baseline (no taint)" if taint_acc == 0 else "Partial" if taint_acc < 0.5 else "Good"
        lines.append(f"| {tool} | {taint_acc:.1%} | {taint_cov:.1%} | {status} |")

    # Timing comparison
    lines.append("\n### Performance\n")
    lines.append("| Tool | Total Scan Time | Avg per Sample |")
    lines.append("|------|-----------------|----------------|")

    for tool in tools:
        m = tool_metrics[tool]
        total = m.get("total_scan_time", 0)
        avg = m.get("avg_scan_time", 0)
        lines.append(f"| {tool} | {total:.1f}s | {avg:.2f}s |")

    return "\n".join(lines)


def generate_detailed_report(
    all_results: Dict[str, List[EvalResult]],
    benchmark_version: str = "1.0",
) -> str:
    """
    Generate a detailed Markdown report with all metrics and analysis.

    Args:
        all_results: Dictionary mapping tool name to list of EvalResult.
        benchmark_version: Version string for the benchmark.

    Returns:
        Complete Markdown report.
    """
    lines = ["# Agent-Vuln-Bench Detailed Evaluation Report\n"]
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Benchmark Version:** {benchmark_version}")
    lines.append(f"**Tools Evaluated:** {', '.join(all_results.keys())}\n")

    # Add comparison matrix
    lines.append(generate_comparison_matrix(all_results))

    # Per-sample breakdown
    lines.append("\n## Per-Sample Results\n")

    for tool_name, results in all_results.items():
        lines.append(f"\n### {tool_name}\n")
        lines.append("| Sample | TP | FN | FP | Recall | Status |")
        lines.append("|--------|----|----|-------|--------|--------|")

        for result in results:
            tp = len(result.true_positives) if result.true_positives else 0
            fn = len(result.false_negatives) if result.false_negatives else 0
            fp = len(result.false_positives) if result.false_positives else 0
            recall = tp / max(tp + fn, 1)
            status = "✅" if fn == 0 else "⚠️" if fn <= 2 else "❌"
            lines.append(f"| {result.sample_id} | {tp} | {fn} | {fp} | {recall:.1%} | {status} |")

    # Key findings
    lines.append("\n## Key Findings\n")

    # Identify which tool is best at each category
    tool_metrics = {t: compute_aggregate_metrics(r) for t, r in all_results.items()}

    # Find best overall
    best_recall_tool = max(tool_metrics.items(), key=lambda x: x[1].get("recall", 0))
    lines.append(f"1. **Best Overall Recall:** {best_recall_tool[0]} ({best_recall_tool[1].get('recall', 0):.1%})")

    # Find best at Set B (MCP)
    best_setb_tool = max(tool_metrics.items(), key=lambda x: x[1].get("set_b_recall", 0))
    setb_recall = best_setb_tool[1].get("set_b_recall", 0)
    if setb_recall > 0:
        lines.append(f"2. **Best at Set B (MCP):** {best_setb_tool[0]} ({setb_recall:.1%})")
        lines.append("   - This is the key differentiator for agent-specific tools")
    else:
        lines.append("2. **Set B (MCP):** No tool detected MCP-specific vulnerabilities")

    # Taint analysis gap
    taint_tools = [(t, m.get("taint_accuracy", 0)) for t, m in tool_metrics.items()]
    max_taint = max(taint_tools, key=lambda x: x[1])
    if max_taint[1] == 0:
        lines.append("3. **Taint Analysis:** All tools at 0% - significant gap to address")
    else:
        lines.append(f"3. **Best Taint Accuracy:** {max_taint[0]} ({max_taint[1]:.1%})")

    # Recommendations
    lines.append("\n## Recommendations\n")
    lines.append("Based on this evaluation:\n")

    if "agent-audit" in tool_metrics:
        aa_metrics = tool_metrics["agent-audit"]
        if aa_metrics.get("set_b_recall", 0) > 0:
            lines.append("- ✅ agent-audit provides unique coverage for MCP/Agent patterns (Set B)")
        if aa_metrics.get("taint_accuracy", 0) == 0:
            lines.append("- 🎯 **Priority:** Implement taint tracking for improved source→sink analysis")
        if aa_metrics.get("recall", 0) < 0.8:
            lines.append(f"- 🎯 **Priority:** Improve overall recall from {aa_metrics.get('recall', 0):.1%} to 80%+")

    return "\n".join(lines)


def generate_json_comparison(
    all_results: Dict[str, List[EvalResult]],
) -> Dict[str, Any]:
    """
    Generate JSON-serializable comparison data.

    Args:
        all_results: Dictionary mapping tool name to list of EvalResult.

    Returns:
        Dictionary with all comparison data.
    """
    return {
        "timestamp": datetime.now().isoformat(),
        "benchmark_version": "1.0",
        "tools": {tool: compute_aggregate_metrics(results) for tool, results in all_results.items()},
        "comparison": {
            "best_recall": max(
                ((t, compute_aggregate_metrics(r).get("recall", 0)) for t, r in all_results.items()),
                key=lambda x: x[1],
            )[0]
            if all_results
            else None,
            "best_set_b": max(
                ((t, compute_aggregate_metrics(r).get("set_b_recall", 0)) for t, r in all_results.items()),
                key=lambda x: x[1],
            )[0]
            if all_results
            else None,
        },
    }
