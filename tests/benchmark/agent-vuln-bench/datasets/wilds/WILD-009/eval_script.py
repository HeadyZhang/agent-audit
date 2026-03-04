#!/usr/bin/env python3
"""
Standalone drift evaluation for WILD-009 (MCP Rug Pull).

This script tests AGENT-054 baseline drift detection, which requires
comparing a baseline against the current state. This cannot be tested
via the standard `agent-audit scan` flow.

Usage:
    cd packages/audit
    poetry run python ../../tests/benchmark/agent-vuln-bench/datasets/wilds/WILD-009/eval_script.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Add packages/audit to path for imports
SAMPLE_DIR = Path(__file__).parent
PACKAGES_AUDIT = SAMPLE_DIR.parent.parent.parent.parent.parent / "packages" / "audit"
sys.path.insert(0, str(PACKAGES_AUDIT))

from agent_audit.scanners.mcp_baseline import MCPBaselineManager


def run_drift_eval():
    """Evaluate AGENT-054 drift detection for this sample."""
    baseline_path = SAMPLE_DIR / "baseline.json"
    current_config_path = SAMPLE_DIR / "current_state" / "mcp_config.json"

    mgr = MCPBaselineManager()

    # Load baseline
    baseline = mgr.load_baseline(str(baseline_path))
    if baseline is None:
        print("FAIL: Could not load baseline.json")
        return False

    # Load current state
    with open(current_config_path) as f:
        current_config = json.load(f)

    # Build inspection data from current config
    current_data = {}
    for server_name, server_config in current_config.get("mcpServers", {}).items():
        current_data[server_name] = {
            "tools": server_config.get("tools", []),
            "resources": [],
            "prompts": [],
        }

    # Run drift detection
    findings = mgr.detect_drift(current_data, baseline)

    # Evaluate results
    drift_types = [f.drift_type for f in findings]
    component_names = [f.component_name for f in findings]

    results = {
        "tool_modified": "tool_modified" in drift_types,
        "tool_added": "tool_added" in drift_types,
        "upload_workspace_added": "upload_workspace" in component_names,
        "read_docs_unchanged": "read_docs" not in component_names,
    }

    print("WILD-009 Drift Evaluation Results:")
    print(f"  Findings: {len(findings)}")
    for f in findings:
        print(f"    - {f.drift_type}: {f.component_name} ({f.server_name})")

    all_pass = all(results.values())
    for check, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {check}")

    print(f"\nOverall: {'PASS' if all_pass else 'FAIL'}")
    return all_pass


if __name__ == "__main__":
    success = run_drift_eval()
    sys.exit(0 if success else 1)
