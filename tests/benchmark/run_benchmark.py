#!/usr/bin/env python3
"""
Standardized Benchmark Runner for agent-audit.

Usage:
    python tests/benchmark/run_benchmark.py [--config benchmark_config.yaml]

Features:
1. Reads target list and scan paths from config
2. Clones/updates repos (locked to specific refs)
3. Executes agent-audit scan for each target
4. Unified ASI category extraction (compatible with old/new field names)
5. Generates standardized report (Markdown + JSON)
6. Compares with previous results, highlights changes

Created: 2026-02-04 for v0.4.0
Reference: agent-audit-v040-final.md Prompt B0
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class TargetConfig:
    """Configuration for a benchmark target."""

    id: str
    name: str
    repo: str
    ref: str
    scan_path: str
    category: str
    expected_min_findings: Optional[int] = None
    expected_max_findings: Optional[int] = None
    expected_asi_min: Optional[int] = None
    description: str = ""


@dataclass
class ScanResult:
    """Result of scanning a single target."""

    target_id: str
    target_name: str
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_rule: Dict[str, int]
    asi_categories: List[str]
    scan_path: str
    scan_duration_seconds: float
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BenchmarkReport:
    """Complete benchmark report."""

    version: str
    timestamp: str
    tool_version: str
    total_targets: int
    successful_scans: int
    failed_scans: int
    results: Dict[str, ScanResult]
    owasp_coverage: List[str]
    quality_assessment: Dict[str, Any]


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load benchmark configuration from YAML file."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def parse_targets(config: Dict[str, Any]) -> List[TargetConfig]:
    """Parse target configurations from config dict."""
    targets = []
    for tid, tconfig in config.get("targets", {}).items():
        targets.append(
            TargetConfig(
                id=tid,
                name=tconfig.get("name", tid),
                repo=tconfig.get("repo", ""),
                ref=tconfig.get("ref", "main"),
                scan_path=tconfig.get("scan_path", "."),
                category=tconfig.get("category", "unknown"),
                expected_min_findings=tconfig.get("expected_min_findings"),
                expected_max_findings=tconfig.get("expected_max_findings"),
                expected_asi_min=tconfig.get("expected_asi_min"),
                description=tconfig.get("description", ""),
            )
        )
    return targets


def clone_or_update_repo(target: TargetConfig, repos_dir: Path) -> Optional[Path]:
    """Clone or update a git repository."""
    if target.repo == "local":
        # Local target, return None to signal local path should be used
        return None

    repo_name = target.name.replace("/", "_")
    repo_path = repos_dir / repo_name

    if repo_path.exists():
        logger.info(f"Updating existing repo: {target.name}")
        try:
            subprocess.run(
                ["git", "fetch", "origin"],
                cwd=repo_path,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "checkout", target.ref],
                cwd=repo_path,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "pull", "origin", target.ref],
                cwd=repo_path,
                check=False,  # May fail if detached HEAD
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to update {target.name}: {e}")
    else:
        logger.info(f"Cloning repo: {target.name}")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "-b", target.ref, target.repo, str(repo_path)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone {target.name}: {e}")
            return None

    return repo_path


def extract_asi_categories(finding: Dict[str, Any]) -> List[str]:
    """
    Extract ASI categories from a finding, compatible with old/new field names.

    This function handles the field name inconsistency between:
    - New field: asi_categories (list)
    - Old field: owasp_agentic_id (string or list)
    - Finding field: owasp_id (string)

    Returns normalized ASI-XX format.
    """
    categories: List[str] = []

    # Priority 1: New field (asi_categories)
    if "asi_categories" in finding:
        cats = finding["asi_categories"]
        if isinstance(cats, list):
            categories.extend(cats)
        elif isinstance(cats, str) and cats:
            categories.append(cats)

    # Priority 2: Finding owasp_id field
    if not categories and "owasp_id" in finding:
        owasp_id = finding["owasp_id"]
        if owasp_id:
            if isinstance(owasp_id, list):
                categories.extend(owasp_id)
            else:
                categories.append(str(owasp_id))

    # Priority 3: Legacy field (owasp_agentic_id)
    if not categories and "owasp_agentic_id" in finding:
        old_id = finding["owasp_agentic_id"]
        if old_id:
            if isinstance(old_id, list):
                categories.extend(old_id)
            else:
                categories.append(str(old_id))

    # Normalize all to ASI-XX format
    normalized: List[str] = []
    for cat in categories:
        cat_str = str(cat).strip().upper()
        if cat_str.startswith("ASI-"):
            normalized.append(cat_str)
        elif cat_str.startswith("OWASP-AGENT-"):
            # Map old format: OWASP-AGENT-01 -> ASI-01
            num = cat_str.replace("OWASP-AGENT-", "").zfill(2)
            normalized.append(f"ASI-{num}")
        elif cat_str.startswith("OWASP-AGENTIC-"):
            num = cat_str.replace("OWASP-AGENTIC-", "").zfill(2)
            normalized.append(f"ASI-{num}")
        elif cat_str.isdigit():
            normalized.append(f"ASI-{cat_str.zfill(2)}")

    return sorted(set(normalized))


def run_scan(scan_path: Path, output_file: Path) -> Optional[Dict[str, Any]]:
    """Run agent-audit scan on a path."""
    import time

    start_time = time.time()

    try:
        result = subprocess.run(
            ["agent-audit", "scan", str(scan_path), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        duration = time.time() - start_time

        if result.returncode != 0 and not result.stdout:
            logger.error(f"Scan failed: {result.stderr}")
            return None

        # Parse JSON output
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Try to find JSON in output (may have warnings before JSON)
            lines = result.stdout.strip().split("\n")
            for i, line in enumerate(lines):
                if line.startswith("{") or line.startswith("["):
                    try:
                        data = json.loads("\n".join(lines[i:]))
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                logger.error(f"Could not parse JSON output: {result.stdout[:200]}")
                return None

        # Save raw output
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        return {"data": data, "duration": duration}

    except subprocess.TimeoutExpired:
        logger.error(f"Scan timed out for {scan_path}")
        return None
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return None


def analyze_results(
    target: TargetConfig, scan_data: Dict[str, Any], duration: float
) -> ScanResult:
    """Analyze scan results for a target."""
    data = scan_data.get("data", {})

    # Handle both list and dict formats
    if isinstance(data, list):
        findings = data
    else:
        findings = data.get("findings", [])

    # Count by severity
    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Count by rule
    rule_counts: Dict[str, int] = {}
    for f in findings:
        rule = f.get("rule_id", "unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

    # Extract all ASI categories
    all_asi: Set[str] = set()
    for f in findings:
        all_asi.update(extract_asi_categories(f))

    return ScanResult(
        target_id=target.id,
        target_name=target.name,
        total_findings=len(findings),
        findings_by_severity=severity_counts,
        findings_by_rule=rule_counts,
        asi_categories=sorted(all_asi),
        scan_path=target.scan_path,
        scan_duration_seconds=duration,
        findings=findings,
    )


def compare_results(current: Dict[str, ScanResult], previous_file: Path) -> Dict[str, Any]:
    """Compare current results with previous benchmark."""
    comparison: Dict[str, Any] = {}

    if not previous_file.exists():
        return comparison

    try:
        with open(previous_file, "r") as f:
            previous = json.load(f)
    except (json.JSONDecodeError, IOError):
        return comparison

    prev_results = previous.get("results", {})

    for tid, cur in current.items():
        prev = prev_results.get(tid, {})
        prev_findings = prev.get("total_findings", 0)
        prev_asi = prev.get("asi_categories", [])

        delta = cur.total_findings - prev_findings
        regression = cur.total_findings > prev_findings * 1.2 if prev_findings > 0 else False

        comparison[tid] = {
            "findings_current": cur.total_findings,
            "findings_previous": prev_findings,
            "delta": delta,
            "delta_percent": (delta / prev_findings * 100) if prev_findings > 0 else 0,
            "asi_current": cur.asi_categories,
            "asi_previous": prev_asi,
            "asi_added": list(set(cur.asi_categories) - set(prev_asi)),
            "asi_removed": list(set(prev_asi) - set(cur.asi_categories)),
            "regression": regression,
        }

    return comparison


def assess_quality(
    results: Dict[str, ScanResult], config: Dict[str, Any]
) -> Dict[str, Any]:
    """Assess benchmark quality against v0.4.0 targets."""
    quality_config = config.get("quality", {})

    # Collect all ASI categories across all targets
    all_asi: Set[str] = set()
    for r in results.values():
        all_asi.update(r.asi_categories)

    owasp_coverage = len(all_asi)

    # Check specific targets
    t1_result = results.get("T1")
    t2_result = results.get("T2")
    t5_result = results.get("T5")

    assessment = {
        "owasp_coverage": {
            "target": quality_config.get("owasp_coverage", 10),
            "actual": owasp_coverage,
            "categories": sorted(all_asi),
            "pass": owasp_coverage >= quality_config.get("owasp_coverage", 10),
        },
        "t1_findings": {
            "target": f">= {quality_config.get('t1_min_findings', 5)}",
            "actual": t1_result.total_findings if t1_result else 0,
            "pass": (t1_result.total_findings >= quality_config.get("t1_min_findings", 5))
            if t1_result
            else False,
        },
        "t2_asi": {
            "target": f">= {quality_config.get('t2_min_asi', 3)}",
            "actual": len(t2_result.asi_categories) if t2_result else 0,
            "categories": t2_result.asi_categories if t2_result else [],
            "pass": (len(t2_result.asi_categories) >= quality_config.get("t2_min_asi", 3))
            if t2_result
            else False,
        },
        "t5_findings": {
            "target": f"< {quality_config.get('t5_max_findings', 90)}",
            "actual": t5_result.total_findings if t5_result else 0,
            "pass": (t5_result.total_findings < quality_config.get("t5_max_findings", 90))
            if t5_result
            else True,
        },
    }

    # Overall pass
    all_pass = all(v.get("pass", False) for v in assessment.values())
    assessment["overall"] = "PASS" if all_pass else "FAIL"

    return assessment


def generate_markdown_report(
    report: BenchmarkReport, comparison: Dict[str, Any], output_path: Path
) -> None:
    """Generate Markdown benchmark report."""
    lines = [
        f"# agent-audit Benchmark Report",
        f"",
        f"**Version:** {report.tool_version}",
        f"**Timestamp:** {report.timestamp}",
        f"**Targets:** {report.successful_scans}/{report.total_targets} successful",
        f"",
        f"## Summary",
        f"",
        f"| ID | Project | Findings | Delta | ASI Categories | Status |",
        f"|----|---------|----------|-------|----------------|--------|",
    ]

    for tid, result in sorted(report.results.items()):
        comp = comparison.get(tid, {})
        delta = comp.get("delta", 0)
        delta_str = f"+{delta}" if delta > 0 else str(delta) if delta != 0 else "-"
        regression = comp.get("regression", False)
        status = "REGRESS" if regression else "OK"

        lines.append(
            f"| {tid} | {result.target_name} | {result.total_findings} | {delta_str} | "
            f"{', '.join(result.asi_categories) or '-'} | {status} |"
        )

    # Quality Assessment
    lines.extend(
        [
            f"",
            f"## Quality Assessment (v0.4.0 Targets)",
            f"",
            f"| Metric | Target | Actual | Pass? |",
            f"|--------|--------|--------|-------|",
        ]
    )

    qa = report.quality_assessment
    for key, value in qa.items():
        if key == "overall":
            continue
        if isinstance(value, dict):
            target = value.get("target", "-")
            actual = value.get("actual", "-")
            passed = "PASS" if value.get("pass") else "FAIL"
            lines.append(f"| {key} | {target} | {actual} | {passed} |")

    lines.extend(
        [
            f"",
            f"**Overall:** {qa.get('overall', 'UNKNOWN')}",
            f"",
            f"## OWASP Coverage",
            f"",
            f"**Categories detected:** {len(report.owasp_coverage)}/10",
            f"",
        ]
    )

    for cat in sorted(report.owasp_coverage):
        lines.append(f"- {cat}")

    # Missing categories
    all_asi = {f"ASI-{str(i).zfill(2)}" for i in range(1, 11)}
    missing = all_asi - set(report.owasp_coverage)
    if missing:
        lines.extend(
            [
                f"",
                f"**Missing categories:** {', '.join(sorted(missing))}",
            ]
        )

    # Write report
    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    logger.info(f"Report written to {output_path}")


def get_tool_version() -> str:
    """Get agent-audit version."""
    try:
        result = subprocess.run(
            ["agent-audit", "--version"],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run agent-audit benchmark")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).parent / "benchmark_config.yaml",
        help="Path to benchmark config file",
    )
    parser.add_argument(
        "--repos-dir",
        type=Path,
        default=Path("/tmp/benchmark/repos"),
        help="Directory to clone repos into",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/benchmark/results"),
        help="Directory for output files",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Specific target IDs to run (default: all)",
    )
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="Skip repo cloning (use existing repos)",
    )
    parser.add_argument(
        "--layer2-json",
        type=Path,
        help="Path for layer2.json output (default: <output-dir>/layer2.json)",
    )
    args = parser.parse_args()

    # Load config
    logger.info(f"Loading config from {args.config}")
    config = load_config(args.config)
    targets = parse_targets(config)

    # Filter targets if specified
    if args.targets:
        targets = [t for t in targets if t.id in args.targets]

    logger.info(f"Running benchmark on {len(targets)} targets")

    # Create directories
    args.repos_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Get tool version
    tool_version = get_tool_version()
    logger.info(f"agent-audit version: {tool_version}")

    # Run scans
    results: Dict[str, ScanResult] = {}
    failed = 0

    for target in targets:
        logger.info(f"=== Processing {target.id}: {target.name} ===")

        # Determine scan path
        if target.repo == "local":
            # Local file/directory
            base_path = Path(__file__).parent.parent.parent  # project root
            scan_path = base_path / target.scan_path
        else:
            # Clone/update repo
            if not args.skip_clone:
                repo_path = clone_or_update_repo(target, args.repos_dir)
                if repo_path is None:
                    logger.error(f"Failed to get repo for {target.name}")
                    failed += 1
                    continue
            else:
                repo_path = args.repos_dir / target.name.replace("/", "_")
                if not repo_path.exists():
                    logger.error(f"Repo not found: {repo_path}")
                    failed += 1
                    continue

            # Construct scan path relative to repo
            if target.scan_path == ".":
                scan_path = repo_path
            else:
                scan_path = repo_path / target.scan_path

        if not scan_path.exists():
            logger.error(f"Scan path does not exist: {scan_path}")
            failed += 1
            continue

        # Run scan
        output_file = args.output_dir / f"{target.id}_{target.name.replace('/', '_')}.json"
        scan_result = run_scan(scan_path, output_file)

        if scan_result is None:
            logger.error(f"Scan failed for {target.name}")
            results[target.id] = ScanResult(
                target_id=target.id,
                target_name=target.name,
                total_findings=0,
                findings_by_severity={},
                findings_by_rule={},
                asi_categories=[],
                scan_path=str(scan_path),
                scan_duration_seconds=0,
                error="Scan failed",
            )
            failed += 1
            continue

        # Analyze results
        result = analyze_results(target, scan_result, scan_result["duration"])
        results[target.id] = result

        logger.info(
            f"  Findings: {result.total_findings}, ASI: {result.asi_categories}, "
            f"Duration: {result.scan_duration_seconds:.1f}s"
        )

    # Collect all ASI categories
    all_asi: Set[str] = set()
    for r in results.values():
        all_asi.update(r.asi_categories)

    # Assess quality
    quality = assess_quality(results, config)

    # Compare with previous results
    previous_file = args.output_dir / "benchmark_comparison.json"
    comparison = compare_results(results, previous_file)

    # Create report
    report = BenchmarkReport(
        version=config.get("version", "1"),
        timestamp=datetime.now().isoformat(),
        tool_version=tool_version,
        total_targets=len(targets),
        successful_scans=len(targets) - failed,
        failed_scans=failed,
        results=results,
        owasp_coverage=sorted(all_asi),
        quality_assessment=quality,
    )

    # Generate markdown report
    report_path = args.output_dir / config.get("output", {}).get(
        "report_file", "benchmark_report.md"
    )
    generate_markdown_report(report, comparison, report_path)

    # Save JSON results for future comparison
    results_json = {
        "version": report.version,
        "timestamp": report.timestamp,
        "tool_version": report.tool_version,
        "results": {
            tid: {
                "total_findings": r.total_findings,
                "findings_by_severity": r.findings_by_severity,
                "findings_by_rule": r.findings_by_rule,
                "asi_categories": r.asi_categories,
                "scan_path": r.scan_path,
                "scan_duration_seconds": r.scan_duration_seconds,
            }
            for tid, r in results.items()
        },
        "owasp_coverage": report.owasp_coverage,
        "quality_assessment": report.quality_assessment,
    }

    json_output = args.output_dir / "benchmark_results.json"
    with open(json_output, "w") as f:
        json.dump(results_json, f, indent=2)
    logger.info(f"JSON results written to {json_output}")

    # Generate layer2.json for quality_gate_check
    max_scan_time = max(
        (r.scan_duration_seconds for r in results.values() if r.scan_duration_seconds > 0),
        default=0.0
    )
    layer2_json = {
        "owasp_coverage": len(all_asi),
        "max_scan_time_seconds": round(max_scan_time, 2),
        "per_target": [
            {
                "target_id": tid,
                "target_name": r.target_name,
                "scan_duration_seconds": round(r.scan_duration_seconds, 2),
                "asi_count": len(r.asi_categories),
                "findings_count": r.total_findings,
            }
            for tid, r in results.items()
        ],
        "timestamp": report.timestamp,
        "tool_version": report.tool_version,
    }
    layer2_output = args.layer2_json if args.layer2_json else args.output_dir / "layer2.json"
    layer2_output.parent.mkdir(parents=True, exist_ok=True)
    with open(layer2_output, "w") as f:
        json.dump(layer2_json, f, indent=2)
    logger.info(f"Layer 2 results written to {layer2_output}")

    # Copy for next comparison
    shutil.copy(json_output, previous_file)

    # Print summary
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Targets: {report.successful_scans}/{report.total_targets} successful")
    print(f"OWASP Coverage: {len(report.owasp_coverage)}/10")
    print(f"Max Scan Time: {max_scan_time:.1f}s")
    print(f"Quality: {quality.get('overall', 'UNKNOWN')}")
    print(f"\nReport: {report_path}")
    print(f"JSON: {json_output}")
    print(f"Layer2: {layer2_output}")

    # Return exit code based on quality
    sys.exit(0 if quality.get("overall") == "PASS" else 1)


if __name__ == "__main__":
    main()
