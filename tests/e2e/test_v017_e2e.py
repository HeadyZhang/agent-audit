"""
End-to-end tests for v0.17.0 MCP security enhancements.

Tests CLI-level behavior with real fixture files.
Validates AGENT-054, AGENT-055, AGENT-056, AGENT-057 detection
across multiple output formats.
"""
import json
import os
import subprocess
import sys

import pytest

from agent_audit.scanners.mcp_baseline import MCPBaselineManager

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def run_scan(target, extra_args=None, fmt="json"):
    """Run agent-audit scan and return parsed output."""
    cmd = [sys.executable, "-m", "agent_audit.cli.main", "scan", target, "--format", fmt]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result


def parse_json_output(result):
    """Parse JSON output from scan, returning dict or empty dict."""
    if result.stdout.strip():
        return json.loads(result.stdout)
    return {}


class TestToolPoisoning:
    """E2E tests for AGENT-056 and AGENT-057."""

    fixture_dir = os.path.join(FIXTURES_DIR, "mcp_poisoning")

    def test_detects_description_poisoning(self):
        """E1: At least one AGENT-056 finding for tool description poisoning."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        rule_ids = [f.get("rule_id") for f in findings]
        assert "AGENT-056" in rule_ids, f"Expected AGENT-056, got: {rule_ids}"

    def test_detects_argument_poisoning(self):
        """E1: At least one AGENT-057 finding for argument description poisoning."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        rule_ids = [f.get("rule_id") for f in findings]
        assert "AGENT-057" in rule_ids, f"Expected AGENT-057, got: {rule_ids}"

    def test_clean_tool_no_false_positive(self):
        """export_data is clean and should not have poisoning findings."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        export_findings = [
            f for f in findings
            if "export_data" in f.get("description", "")
            and f.get("rule_id") in ("AGENT-056", "AGENT-057")
        ]
        assert len(export_findings) == 0, f"False positive on export_data: {export_findings}"

    def test_poisoning_findings_have_correct_category(self):
        """Poisoning findings should be in goal_hijack category."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        for f in findings:
            if f.get("rule_id") in ("AGENT-056", "AGENT-057"):
                assert f.get("category") == "goal_hijack", (
                    f"Expected goal_hijack category, got: {f.get('category')}"
                )


class TestToolShadowing:
    """E2E tests for AGENT-055."""

    fixture_dir = os.path.join(FIXTURES_DIR, "mcp_shadowing")

    def test_detects_exact_shadowing(self):
        """E2: read_file appears in both servers -> AGENT-055."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        shadowing_findings = [f for f in findings if f.get("rule_id") == "AGENT-055"]
        assert len(shadowing_findings) >= 1, (
            f"Expected AGENT-055, got: {[f.get('rule_id') for f in findings]}"
        )

    def test_shadowing_mentions_read_file(self):
        """AGENT-055 finding should reference the shadowed tool name."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        shadowing_findings = [f for f in findings if f.get("rule_id") == "AGENT-055"]
        assert any(
            "read_file" in f.get("description", "") for f in shadowing_findings
        ), f"Expected 'read_file' in description: {shadowing_findings}"


class TestBaselineDrift:
    """E2E tests for AGENT-054 baseline drift detection (offline mode)."""

    fixture_dir = os.path.join(FIXTURES_DIR, "mcp_drift")

    def test_drift_detected_offline(self):
        """E3: Offline drift detection finds tool_modified and tool_added."""
        baseline_path = os.path.join(self.fixture_dir, "baseline.json")
        current_config_path = os.path.join(self.fixture_dir, "current_state", "mcp.json")

        mgr = MCPBaselineManager()
        baseline = mgr.load_baseline(baseline_path)
        assert baseline is not None, "Failed to load baseline"

        with open(current_config_path) as f:
            current_config = json.load(f)

        current_data = {}
        for server_name, server_config in current_config.get("mcpServers", {}).items():
            current_data[server_name] = {
                "tools": server_config.get("tools", []),
                "resources": [],
                "prompts": [],
            }

        findings = mgr.detect_drift(current_data, baseline)
        drift_types = [f.drift_type for f in findings]

        assert "tool_modified" in drift_types, f"Expected tool_modified, got: {drift_types}"
        assert "tool_added" in drift_types, f"Expected tool_added, got: {drift_types}"

    def test_no_drift_for_unchanged_tool(self):
        """read_docs is unchanged -> should not appear in drift findings."""
        baseline_path = os.path.join(self.fixture_dir, "baseline.json")
        current_config_path = os.path.join(self.fixture_dir, "current_state", "mcp.json")

        mgr = MCPBaselineManager()
        baseline = mgr.load_baseline(baseline_path)

        with open(current_config_path) as f:
            current_config = json.load(f)

        current_data = {}
        for server_name, server_config in current_config.get("mcpServers", {}).items():
            current_data[server_name] = {
                "tools": server_config.get("tools", []),
                "resources": [],
                "prompts": [],
            }

        findings = mgr.detect_drift(current_data, baseline)
        read_docs_findings = [f for f in findings if f.component_name == "read_docs"]
        assert len(read_docs_findings) == 0, (
            f"read_docs should have no drift: {read_docs_findings}"
        )

    def test_drift_upload_workspace_added(self):
        """upload_workspace is a new tool -> tool_added drift."""
        baseline_path = os.path.join(self.fixture_dir, "baseline.json")
        current_config_path = os.path.join(self.fixture_dir, "current_state", "mcp.json")

        mgr = MCPBaselineManager()
        baseline = mgr.load_baseline(baseline_path)

        with open(current_config_path) as f:
            current_config = json.load(f)

        current_data = {}
        for server_name, server_config in current_config.get("mcpServers", {}).items():
            current_data[server_name] = {
                "tools": server_config.get("tools", []),
                "resources": [],
                "prompts": [],
            }

        findings = mgr.detect_drift(current_data, baseline)
        added = [f for f in findings if f.drift_type == "tool_added"]
        assert any(f.component_name == "upload_workspace" for f in added), (
            f"Expected upload_workspace in added tools: {[f.component_name for f in added]}"
        )


class TestSarifOutput:
    """Verify new rules appear correctly in SARIF format."""

    fixture_dir = os.path.join(FIXTURES_DIR, "mcp_poisoning")

    def _parse_sarif(self, raw_output):
        """Parse SARIF output, tolerant of control chars from Rich console."""
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            return json.loads(raw_output, strict=False)

    def test_sarif_contains_new_rules(self):
        """E4: SARIF output includes v0.17.0 rules."""
        result = run_scan(self.fixture_dir, fmt="sarif")
        if not result.stdout.strip():
            pytest.skip("No SARIF output")
        sarif = self._parse_sarif(result.stdout)
        runs = sarif.get("runs", [])
        assert len(runs) > 0, "SARIF should have at least one run"
        results = runs[0].get("results", [])
        result_rule_ids = [r.get("ruleId") for r in results]
        new_rules = {"AGENT-056", "AGENT-057"}
        found = new_rules.intersection(set(result_rule_ids))
        assert len(found) > 0, f"No new rules in SARIF results. Got: {result_rule_ids}"

    def test_sarif_valid_structure(self):
        """SARIF output has valid $schema and version fields."""
        result = run_scan(self.fixture_dir, fmt="sarif")
        if not result.stdout.strip():
            pytest.skip("No SARIF output")
        sarif = self._parse_sarif(result.stdout)
        assert "$schema" in sarif or "version" in sarif, "SARIF missing schema or version"


class TestJsonOutput:
    """Verify JSON output format for combined fixture."""

    fixture_dir = os.path.join(FIXTURES_DIR, "combined")

    def test_json_contains_new_rules(self):
        """E5: JSON output includes v0.17.0 rules."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        findings = output.get("findings", [])
        rule_ids = set(f.get("rule_id") for f in findings)
        new_rules_found = rule_ids.intersection({"AGENT-055", "AGENT-056", "AGENT-057"})
        assert len(new_rules_found) > 0, f"Expected new rules, got: {rule_ids}"

    def test_json_version_is_017(self):
        """JSON output version field should be 0.17.0."""
        result = run_scan(self.fixture_dir)
        output = parse_json_output(result)
        assert output.get("version") == "0.17.0", (
            f"Expected version 0.17.0, got: {output.get('version')}"
        )


class TestVersionBump:
    """Verify version number is correct."""

    def test_version_is_017(self):
        """E7: CLI version shows 0.17.0."""
        result = subprocess.run(
            [sys.executable, "-m", "agent_audit.cli.main", "--version"],
            capture_output=True, text=True, timeout=10
        )
        combined = result.stdout + result.stderr
        assert "0.17.0" in combined, f"Version not 0.17.0: {combined}"
