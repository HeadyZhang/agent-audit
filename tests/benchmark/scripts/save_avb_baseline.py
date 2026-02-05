#!/usr/bin/env python3
"""
Baseline Generator for Agent-Vuln-Bench.

Generates a baseline file from run_eval results for regression testing.

Usage:
    python save_avb_baseline.py --eval-results results/avb_results.json --output results/baseline.json
    python save_avb_baseline.py --output results/baseline.json  # Runs run_eval internally

The baseline file contains:
- version: benchmark version (e.g., "v0.5.0")
- date: ISO date of baseline generation
- passing_samples: list of sample IDs that passed (no false negatives)
- metrics: overall recall, precision, f1, and per-set metrics
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def extract_passing_samples(eval_results: Dict[str, Any]) -> List[str]:
    """
    Extract list of passing sample IDs from run_eval results.

    A sample passes if it has zero false negatives.
    """
    passing = []

    # Handle different result formats
    if "samples" in eval_results:
        # Direct samples array format
        for sample in eval_results.get("samples", []):
            if sample.get("fn_count", 0) == 0:
                passing.append(sample.get("sample_id", ""))
    elif isinstance(eval_results, dict):
        # Multi-tool format or nested format
        for tool_name, tool_data in eval_results.items():
            if isinstance(tool_data, dict) and "samples" in tool_data:
                for sample in tool_data.get("samples", []):
                    if sample.get("fn_count", 0) == 0:
                        passing.append(sample.get("sample_id", ""))
                break  # Only use first tool's samples

    return sorted(set(passing))


def extract_metrics(eval_results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract overall metrics from run_eval results."""
    metrics = {}

    # Handle CI format (overall, set_A, etc.)
    if "overall" in eval_results:
        metrics["recall"] = eval_results["overall"].get("recall", 0)
        metrics["precision"] = eval_results["overall"].get("precision", 0)
        metrics["f1"] = eval_results["overall"].get("f1", 0)
        for set_key in ["set_A", "set_B", "set_C"]:
            if set_key in eval_results:
                metrics[f"{set_key.lower()}_recall"] = eval_results[set_key].get("recall", 0)
        return metrics

    # Handle multi-tool format
    for tool_name, tool_data in eval_results.items():
        if isinstance(tool_data, dict) and "metrics" in tool_data:
            m = tool_data["metrics"]
            metrics["recall"] = m.get("recall", 0)
            metrics["precision"] = m.get("precision", 0)
            metrics["f1"] = m.get("f1", 0)
            metrics["set_a_recall"] = m.get("set_a_recall", 0)
            metrics["set_b_recall"] = m.get("set_b_recall", 0)
            metrics["set_c_recall"] = m.get("set_c_recall", 0)
            break  # Only use first tool's metrics

    return metrics


def run_eval_internal(output_path: Path) -> Dict[str, Any]:
    """Run run_eval.py internally and return results."""
    # Determine paths
    script_dir = Path(__file__).parent
    run_eval_path = script_dir.parent / "agent-vuln-bench" / "harness" / "run_eval.py"

    if not run_eval_path.exists():
        print(f"Error: run_eval.py not found at {run_eval_path}")
        sys.exit(1)

    temp_output = output_path.parent / "temp_eval_results.json"

    print(f"Running run_eval.py...")
    result = subprocess.run(
        [
            sys.executable,
            str(run_eval_path),
            "--tool", "agent-audit",
            "--dataset", "all",
            "--output", str(temp_output),
        ],
        capture_output=True,
        text=True,
    )

    if not temp_output.exists():
        print(f"Error: run_eval failed to produce output")
        print(result.stderr)
        sys.exit(1)

    with open(temp_output) as f:
        eval_results = json.load(f)

    # Clean up temp file
    temp_output.unlink()

    return eval_results


def generate_baseline(
    eval_results: Dict[str, Any],
    version: str = "v0.5.0",
) -> Dict[str, Any]:
    """Generate baseline structure from eval results."""
    passing_samples = extract_passing_samples(eval_results)
    metrics = extract_metrics(eval_results)

    return {
        "version": version,
        "date": datetime.now().isoformat(),
        "passing_samples": passing_samples,
        "metrics": metrics,
        "sample_count": len(passing_samples),
    }


def main():
    parser = argparse.ArgumentParser(description="Generate AVB baseline from run_eval results")
    parser.add_argument(
        "--eval-results",
        type=Path,
        help="Path to run_eval output JSON (if not provided, runs run_eval internally)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/baseline.json"),
        help="Output path for baseline JSON (default: results/baseline.json)",
    )
    parser.add_argument(
        "--version",
        default="v0.5.0",
        help="Version string for baseline (default: v0.5.0)",
    )
    args = parser.parse_args()

    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)

    # Get eval results
    if args.eval_results and args.eval_results.exists():
        print(f"Loading eval results from {args.eval_results}")
        with open(args.eval_results) as f:
            eval_results = json.load(f)
    elif args.eval_results:
        print(f"Error: eval results file not found: {args.eval_results}")
        sys.exit(1)
    else:
        print("No eval results provided, running run_eval internally...")
        eval_results = run_eval_internal(args.output)

    # Generate baseline
    baseline = generate_baseline(eval_results, version=args.version)

    # Write baseline
    with open(args.output, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"\n✅ Baseline written to {args.output}")
    print(f"   Version: {baseline['version']}")
    print(f"   Date: {baseline['date']}")
    print(f"   Passing samples: {baseline['sample_count']}")
    print(f"   Recall: {baseline['metrics'].get('recall', 0):.1%}")
    print(f"   Precision: {baseline['metrics'].get('precision', 0):.1%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
