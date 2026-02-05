#!/usr/bin/env python3
"""
Agent-Vuln-Bench Evaluation Script

SWE-bench style automated benchmark evaluation for AI agent security tools.

Usage:
    python run_eval.py                           # Default: agent-audit, all datasets
    python run_eval.py --tool agent-audit        # Specify tool
    python run_eval.py --tool bandit             # Bandit baseline
    python run_eval.py --tool all                # All available tools
    python run_eval.py --dataset knowns          # Only CVE samples
    python run_eval.py --dataset wilds           # Only wild samples
    python run_eval.py --dataset noise           # Only noise projects
    python run_eval.py --set A                   # Only Set A vulnerabilities
    python run_eval.py --output results/v041/    # Specify output directory
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Add parent directories to path for imports
BENCH_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BENCH_ROOT.parent.parent.parent))

from .adapters.agent_audit_adapter import AgentAuditAdapter
from .adapters.bandit_adapter import BanditAdapter
from .adapters.base_adapter import BaseAdapter, ToolFinding, ToolNotAvailable
from .adapters.semgrep_adapter import SemgrepAdapter
from .oracle_eval import EvalResult, evaluate_sample

try:
    from ..metrics.compute_metrics import compute_metrics_enhanced
except ImportError:
    compute_metrics_enhanced = None

try:
    from ..metrics.compare_tools import generate_detailed_report, generate_json_comparison
except ImportError:
    generate_detailed_report = None
    generate_json_comparison = None


def get_adapter(tool_name: str) -> BaseAdapter:
    """Get adapter for a tool by name."""
    adapters = {
        "agent-audit": AgentAuditAdapter,
        "bandit": BanditAdapter,
        "semgrep": SemgrepAdapter,
    }
    if tool_name not in adapters:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(adapters.keys())}")
    return adapters[tool_name]()


def get_all_adapters() -> List[BaseAdapter]:
    """Get all available adapters."""
    adapters = []
    for name in ["agent-audit", "bandit", "semgrep"]:
        try:
            adapter = get_adapter(name)
            if adapter.is_available():
                adapters.append(adapter)
            else:
                print(f"  ⚠ {name} not available")
        except ToolNotAvailable as e:
            print(f"  ⚠ {name}: {e}")
    return adapters


def load_catalog() -> Dict[str, Any]:
    """Load the datasets catalog."""
    catalog_path = BENCH_ROOT / "datasets" / "catalog.yaml"
    with open(catalog_path) as f:
        return yaml.safe_load(f)


def get_samples(
    catalog: Dict[str, Any],
    dataset_filter: str,
    set_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get samples from catalog based on filters.

    Args:
        catalog: Parsed catalog.yaml
        dataset_filter: 'all', 'knowns', 'wilds', or 'noise'
        set_filter: Optional 'A', 'B', or 'C' to filter by set

    Returns:
        List of sample configs with 'id', 'dir', 'vuln_path' keys.
    """
    samples = []
    datasets = catalog.get("datasets", {})

    def add_samples(dataset_type: str, entries: List[Dict[str, Any]]):
        for entry in entries:
            sample_id = entry.get("id", "")

            # Determine paths based on dataset type
            if dataset_type == "knowns":
                sample_dir = BENCH_ROOT / "datasets" / "knowns" / sample_id
                vuln_path = sample_dir / "vuln"
            elif dataset_type == "wilds":
                sample_dir = BENCH_ROOT / "datasets" / "wilds" / sample_id
                vuln_path = sample_dir / "vuln"
            elif dataset_type == "noise":
                sample_dir = BENCH_ROOT / "datasets" / "noise" / f"{sample_id}_{entry.get('source', '')}"
                # Noise samples point to external repos - skip for now
                vuln_path = sample_dir
            else:
                continue

            # Apply set filter
            if set_filter:
                entry_set = entry.get("set", "")
                if entry_set != set_filter and entry_set != "mixed":
                    continue

            if sample_dir.exists():
                samples.append({
                    "id": sample_id,
                    "dir": str(sample_dir),
                    "vuln_path": str(vuln_path),
                    "type": dataset_type,
                    "set": entry.get("set", ""),
                    "source": entry.get("source", ""),
                })

    if dataset_filter in ("all", "knowns"):
        add_samples("knowns", datasets.get("knowns", []))
    if dataset_filter in ("all", "wilds"):
        add_samples("wilds", datasets.get("wilds", []))
    if dataset_filter in ("all", "noise"):
        add_samples("noise", datasets.get("noise", []))

    return samples


def run_evaluation(
    adapter: BaseAdapter,
    samples: List[Dict[str, Any]],
) -> List[EvalResult]:
    """
    Run evaluation for a single tool on all samples.

    Args:
        adapter: Tool adapter to use.
        samples: List of sample configs.

    Returns:
        List of EvalResult for each sample.
    """
    results = []
    tool_name = adapter.get_tool_name()

    for sample in samples:
        sample_id = sample["id"]
        vuln_path = sample["vuln_path"]

        if not Path(vuln_path).exists():
            print(f"  ⚠ {sample_id}: vuln_path not found, skipping")
            continue

        print(f"  Scanning {sample_id}...", end=" ", flush=True)
        start_time = time.time()

        try:
            findings = adapter.scan(vuln_path)
            elapsed = time.time() - start_time

            result = evaluate_sample(sample["dir"], findings, tool_name)
            result.scan_time = elapsed

            tp = len(result.true_positives)
            fn = len(result.false_negatives)
            fp = len(result.false_positives)

            print(f"TP:{tp} FN:{fn} FP:{fp} ({elapsed:.1f}s)")
            results.append(result)

        except ToolNotAvailable as e:
            print(f"ERROR: {e}")
        except Exception as e:
            print(f"ERROR: {e}")

    return results


def compute_aggregate_metrics(results: List[EvalResult]) -> Dict[str, Any]:
    """Compute aggregate metrics from multiple sample results."""
    if not results:
        return {}

    total_tp = sum(len(r.true_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    total_fp = sum(len(r.false_positives) for r in results)

    # Core metrics
    recall = total_tp / max(total_tp + total_fn, 1)
    precision = total_tp / max(total_tp + total_fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    fpr = total_fp / max(total_fp + total_tp, 1)

    # Per-set metrics
    set_a_tp = sum(r.set_a_tp for r in results)
    set_a_total = sum(r.set_a_total for r in results)
    set_b_tp = sum(r.set_b_tp for r in results)
    set_b_total = sum(r.set_b_total for r in results)
    set_c_tp = sum(r.set_c_tp for r in results)
    set_c_total = sum(r.set_c_total for r in results)

    # Taint metrics
    taint_correct = sum(r.taint_correct for r in results)
    taint_partial = sum(r.taint_partial for r in results)
    taint_total = taint_correct + taint_partial + sum(r.taint_missed for r in results)
    taint_accuracy = taint_correct / max(taint_total, 1)

    # Timing
    total_time = sum(r.scan_time for r in results)

    return {
        "total_samples": len(results),
        "total_tp": total_tp,
        "total_fn": total_fn,
        "total_fp": total_fp,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "set_a_recall": round(set_a_tp / max(set_a_total, 1), 4),
        "set_a_total": set_a_total,
        "set_b_recall": round(set_b_tp / max(set_b_total, 1), 4),
        "set_b_total": set_b_total,
        "set_c_recall": round(set_c_tp / max(set_c_total, 1), 4),
        "set_c_total": set_c_total,
        "taint_accuracy": round(taint_accuracy, 4),
        "taint_total": taint_total,
        "total_scan_time": round(total_time, 2),
    }


def generate_report(
    all_results: Dict[str, List[EvalResult]],
    output_dir: Path,
) -> str:
    """Generate Markdown report."""
    lines = ["# Agent-Vuln-Bench Evaluation Report\n"]
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(f"**Benchmark Version:** 1.0\n")

    # Overview
    lines.append("\n## Overview\n")
    for tool_name, results in all_results.items():
        metrics = compute_aggregate_metrics(results)
        lines.append(f"\n### {tool_name}\n")
        lines.append(f"- Samples evaluated: {metrics.get('total_samples', 0)}")
        lines.append(f"- Total TP: {metrics.get('total_tp', 0)}")
        lines.append(f"- Total FN: {metrics.get('total_fn', 0)}")
        lines.append(f"- Total FP: {metrics.get('total_fp', 0)}")
        lines.append(f"- **Recall:** {metrics.get('recall', 0):.1%}")
        lines.append(f"- **Precision:** {metrics.get('precision', 0):.1%}")
        lines.append(f"- **F1:** {metrics.get('f1', 0):.4f}")
        lines.append(f"- Scan time: {metrics.get('total_scan_time', 0):.1f}s")

    # Per-Set breakdown
    lines.append("\n## Per-Set Recall\n")
    lines.append("| Tool | Set A (Injection) | Set B (MCP) | Set C (Data) |")
    lines.append("|------|-------------------|-------------|--------------|")
    for tool_name, results in all_results.items():
        metrics = compute_aggregate_metrics(results)
        a = f"{metrics.get('set_a_recall', 0):.1%}"
        b = f"{metrics.get('set_b_recall', 0):.1%}"
        c = f"{metrics.get('set_c_recall', 0):.1%}"
        lines.append(f"| {tool_name} | {a} | {b} | {c} |")

    # Taint accuracy
    lines.append("\n## Taint Analysis Depth\n")
    lines.append("| Tool | Taint Accuracy | Note |")
    lines.append("|------|----------------|------|")
    for tool_name, results in all_results.items():
        metrics = compute_aggregate_metrics(results)
        taint = f"{metrics.get('taint_accuracy', 0):.1%}"
        note = "v0.4.x baseline" if metrics.get('taint_accuracy', 0) == 0 else ""
        lines.append(f"| {tool_name} | {taint} | {note} |")

    # Per-sample details
    lines.append("\n## Per-Sample Results\n")
    for tool_name, results in all_results.items():
        lines.append(f"\n### {tool_name}\n")
        for result in results:
            tp = len(result.true_positives)
            fn = len(result.false_negatives)
            fp = len(result.false_positives)
            status = "✅" if fn == 0 else "⚠️"
            lines.append(f"- {status} **{result.sample_id}**: TP={tp}, FN={fn}, FP={fp}")

    return "\n".join(lines)


def check_regression(
    current_passing: List[str],
    baseline_path: Path,
) -> Dict[str, Any]:
    """Compare current passing samples to baseline; return regression info."""
    if not baseline_path.exists():
        return {"regression_free": True, "newly_passing": [], "newly_failing": []}
    try:
        with open(baseline_path) as f:
            baseline = json.load(f)
    except Exception:
        return {"regression_free": True, "newly_passing": [], "newly_failing": []}
    prev = set(baseline.get("passing_samples", []))
    curr = set(current_passing)
    return {
        "regression_free": len(prev - curr) == 0,
        "newly_passing": sorted(curr - prev),
        "newly_failing": sorted(prev - curr),
        "total_prev": len(prev),
        "total_curr": len(curr),
    }


def save_results(
    all_results: Dict[str, List[EvalResult]],
    output_dir: str,
    report_path: Optional[str] = None,
    baseline_path: Optional[Path] = None,
    output_json_path: Optional[str] = None,
    comparison_report_path: Optional[str] = None,
) -> None:
    """Save results to output directory and optionally CI-friendly JSON."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Save JSON data (multi-tool)
    json_data = {}
    for tool_name, results in all_results.items():
        json_data[tool_name] = {
            "metrics": compute_aggregate_metrics(results),
            "samples": [
                {
                    "sample_id": r.sample_id,
                    "tp_count": len(r.true_positives),
                    "fn_count": len(r.false_negatives),
                    "fp_count": len(r.false_positives),
                    "recall": r.recall,
                    "precision": r.precision,
                    "scan_time": r.scan_time,
                }
                for r in results
            ],
        }

    with open(output_path / "results.json", "w") as f:
        json.dump(json_data, f, indent=2)

    # CI-friendly single-file output (overall + set_A/B/C for first tool)
    if output_json_path or (str(output_path).endswith(".json")):
        out_json = Path(output_json_path or output_dir)
        tool_name = next(iter(all_results), None)
        results_list = all_results.get(tool_name or "", [])
        if compute_metrics_enhanced and results_list:
            ci_metrics = compute_metrics_enhanced(results_list)
            passing = [r.sample_id for r in results_list if len(r.false_negatives) == 0]
            if baseline_path:
                ci_metrics["regression"] = check_regression(passing, baseline_path)
            with open(out_json, "w") as f:
                json.dump(ci_metrics, f, indent=2)
            print(f"✅ CI metrics written to {out_json}")
        elif tool_name and results_list:
            base = compute_aggregate_metrics(results_list)
            ci_metrics = {
                "overall": {"recall": base.get("recall", 0), "precision": base.get("precision", 0), "f1": base.get("f1", 0)},
                "set_A": {"recall": base.get("set_a_recall", 0), "sample_count": base.get("set_a_total", 0)},
                "set_B": {"recall": base.get("set_b_recall", 0), "sample_count": base.get("set_b_total", 0)},
                "set_C": {"recall": base.get("set_c_recall", 0), "sample_count": base.get("set_c_total", 0)},
            }
            if baseline_path:
                passing = [r.sample_id for r in results_list if len(r.false_negatives) == 0]
                ci_metrics["regression"] = check_regression(passing, baseline_path)
            with open(out_json, "w") as f:
                json.dump(ci_metrics, f, indent=2)
            print(f"✅ CI metrics written to {out_json}")

    # Save Markdown report
    report = generate_report(all_results, output_path)
    report_file = Path(report_path) if report_path else (output_path / "report.md")
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w") as f:
        f.write(report)

    # Generate multi-tool comparison report when multiple tools are evaluated
    if len(all_results) > 1 and generate_detailed_report is not None:
        comparison_path = Path(comparison_report_path) if comparison_report_path else (output_path / "comparison_report.md")
        comparison_path.parent.mkdir(parents=True, exist_ok=True)
        comparison_md = generate_detailed_report(all_results)
        with open(comparison_path, "w") as f:
            f.write(comparison_md)
        print(f"✅ Comparison report written to {comparison_path}")

        # Also generate comparison JSON
        if generate_json_comparison is not None:
            comparison_json_path = output_path / "comparison_results.json"
            comparison_json = generate_json_comparison(all_results)
            with open(comparison_json_path, "w") as f:
                json.dump(comparison_json, f, indent=2)
            print(f"✅ Comparison JSON written to {comparison_json_path}")

    print(f"\n✅ Results saved to {output_path}/")


def main():
    parser = argparse.ArgumentParser(description="Agent-Vuln-Bench Evaluation")
    parser.add_argument(
        "--tool",
        default="agent-audit",
        choices=["agent-audit", "bandit", "semgrep", "all"],
        help="Tool to evaluate (default: agent-audit)",
    )
    parser.add_argument(
        "--dataset",
        default="all",
        choices=["all", "knowns", "wilds", "noise"],
        help="Dataset to use (default: all)",
    )
    parser.add_argument(
        "--set",
        default=None,
        choices=["A", "B", "C"],
        help="Filter by vulnerability set",
    )
    parser.add_argument(
        "--output",
        default=str(BENCH_ROOT / "results" / "latest"),
        help="Output directory for results (or .json file for CI metrics)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Path for Markdown report (default: <output>/report.md)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline JSON for regression check (passing_samples list)",
    )
    parser.add_argument(
        "--comparison-report",
        default=None,
        help="Path for multi-tool comparison report (default: <output>/comparison_report.md)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Agent-Vuln-Bench Evaluation")
    print("=" * 60)

    # Load catalog and get samples
    catalog = load_catalog()
    samples = get_samples(catalog, args.dataset, args.set)
    print(f"\n📦 Loaded {len(samples)} samples ({args.dataset})")

    if not samples:
        print("❌ No samples found!")
        return 1

    # Get tools
    if args.tool == "all":
        print("\n🔧 Checking available tools...")
        adapters = get_all_adapters()
    else:
        try:
            adapter = get_adapter(args.tool)
            adapters = [adapter]
        except ToolNotAvailable as e:
            print(f"❌ {e}")
            return 1

    if not adapters:
        print("❌ No tools available!")
        return 1

    # Run evaluation for each tool
    all_results: Dict[str, List[EvalResult]] = {}

    for adapter in adapters:
        tool_name = adapter.get_tool_name()
        print(f"\n{'='*60}")
        print(f"🔍 Evaluating: {tool_name}")
        print(f"{'='*60}")

        try:
            version = adapter.get_tool_version()
            print(f"  Version: {version}")
        except Exception:
            print("  Version: unknown")

        results = run_evaluation(adapter, samples)
        all_results[tool_name] = results

        # Print summary
        metrics = compute_aggregate_metrics(results)
        print(f"\n  Summary for {tool_name}:")
        print(f"    Recall: {metrics.get('recall', 0):.1%}")
        print(f"    Precision: {metrics.get('precision', 0):.1%}")
        print(f"    F1: {metrics.get('f1', 0):.4f}")

    # Save results
    output_path = args.output
    output_is_file = output_path.strip().endswith(".json")
    output_dir = str(Path(output_path).parent) if output_is_file else output_path
    if output_is_file:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    save_results(
        all_results,
        output_dir,
        report_path=args.report,
        baseline_path=Path(args.baseline) if args.baseline else None,
        output_json_path=output_path if output_is_file else None,
        comparison_report_path=args.comparison_report,
    )

    # Final summary
    print("\n" + "=" * 60)
    print("📊 Final Summary")
    print("=" * 60)
    for tool_name, results in all_results.items():
        metrics = compute_aggregate_metrics(results)
        print(f"\n{tool_name}:")
        print(f"  Recall: {metrics.get('recall', 0):.1%} | Precision: {metrics.get('precision', 0):.1%}")
        print(f"  Set A: {metrics.get('set_a_recall', 0):.1%} | Set B: {metrics.get('set_b_recall', 0):.1%} | Set C: {metrics.get('set_c_recall', 0):.1%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
