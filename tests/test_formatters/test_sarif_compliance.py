"""SARIF 2.1.0 compliance tests (v0.15.0).

Verifies SARIF output meets GitHub Code Scanning and Defect Dojo requirements.
"""

from __future__ import annotations

import pytest
from datetime import datetime

from agent_audit.cli.formatters.sarif import SARIFFormatter, _get_mime_type
from agent_audit.models.finding import Finding, Remediation
from agent_audit.models.risk import Severity, Category, Location


def create_test_finding(
    rule_id: str = "AGENT-001",
    severity: Severity = Severity.HIGH,
    cwe_id: str = "CWE-78",
    owasp_id: str = "ASI-02"
) -> Finding:
    """Create a test finding for SARIF tests."""
    return Finding(
        rule_id=rule_id,
        title="Test Finding",
        description="This is a test finding",
        severity=severity,
        category=Category.COMMAND_INJECTION,
        location=Location(
            file_path="src/agent.py",
            start_line=42,
            end_line=42,
            snippet="eval(user_input)"
        ),
        cwe_id=cwe_id,
        owasp_id=owasp_id,
        remediation=Remediation(
            description="Use safe alternatives"
        ),
        confidence=0.85,
    )


class TestSARIFCompliance:
    """Verify SARIF output meets 2.1.0 specification."""

    def test_sarif_has_required_fields(self):
        """SARIF must have $schema, version, runs."""
        formatter = SARIFFormatter()
        findings = [create_test_finding()]
        result = formatter.format(findings)

        assert "$schema" in result
        assert "sarif-schema-2.1.0" in result["$schema"]
        assert result["version"] == "2.1.0"
        assert "runs" in result
        assert len(result["runs"]) == 1

    def test_sarif_run_has_tool_driver(self):
        """Each run must have tool.driver with required fields."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding()])

        run = result["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]

        driver = run["tool"]["driver"]
        assert "name" in driver
        assert driver["name"] == "agent-audit"
        assert "version" in driver
        assert "rules" in driver

    def test_sarif_run_has_invocations(self):
        """Each run must have invocations (v0.15.0)."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding()])

        run = result["runs"][0]
        assert "invocations" in run
        assert len(run["invocations"]) == 1

        invocation = run["invocations"][0]
        assert "executionSuccessful" in invocation
        assert invocation["executionSuccessful"] is True
        assert "commandLine" in invocation
        assert "startTimeUtc" in invocation
        assert "endTimeUtc" in invocation

    def test_sarif_invocations_from_context(self):
        """Invocations should use scan_context values."""
        formatter = SARIFFormatter()
        context = {
            "command_line": "agent-audit scan /path/to/code",
            "start_time": "2026-02-05T10:00:00Z",
            "end_time": "2026-02-05T10:00:05Z",
        }
        result = formatter.format([create_test_finding()], scan_context=context)

        invocation = result["runs"][0]["invocations"][0]
        assert invocation["commandLine"] == "agent-audit scan /path/to/code"
        assert invocation["startTimeUtc"] == "2026-02-05T10:00:00Z"
        assert invocation["endTimeUtc"] == "2026-02-05T10:00:05Z"

    def test_sarif_has_artifacts_when_files_provided(self):
        """Artifacts section should be included when scanned_files provided."""
        formatter = SARIFFormatter()
        context = {
            "scanned_files": ["src/agent.py", "src/tools.py", "config.json"]
        }
        result = formatter.format([create_test_finding()], scan_context=context)

        run = result["runs"][0]
        assert "artifacts" in run
        assert len(run["artifacts"]) == 3

        # Check artifact structure
        artifact = run["artifacts"][0]
        assert "location" in artifact
        assert "uri" in artifact["location"]
        assert "mimeType" in artifact

    def test_sarif_no_artifacts_when_no_files(self):
        """Artifacts section should be omitted when no files scanned."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding()])

        run = result["runs"][0]
        # Artifacts should not be present (empty list case)
        assert run.get("artifacts", []) == [] or "artifacts" not in run

    def test_sarif_rules_have_security_severity(self):
        """Rules should have security-severity property."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding(severity=Severity.CRITICAL)])

        rules = result["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

        rule = rules[0]
        assert "properties" in rule
        assert "security-severity" in rule["properties"]
        # CRITICAL should map to 9.8
        assert rule["properties"]["security-severity"] == "9.8"

    def test_sarif_rules_have_cwe_tags(self):
        """Rules should have CWE in tags when cwe_id is set."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding(cwe_id="CWE-78")])

        rule = result["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" in rule
        assert "tags" in rule["properties"]

        tags = rule["properties"]["tags"]
        assert any("cwe" in tag.lower() for tag in tags)

    def test_sarif_rules_have_owasp_agentic_tags(self):
        """Rules should have OWASP-Agentic tags for ASI-XX IDs."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding(owasp_id="ASI-02")])

        rule = result["runs"][0]["tool"]["driver"]["rules"][0]
        tags = rule["properties"]["tags"]
        assert any("OWASP-Agentic-ASI-02" in tag for tag in tags)

    def test_sarif_results_have_locations(self):
        """Results should have proper location information."""
        formatter = SARIFFormatter()
        result = formatter.format([create_test_finding()])

        results = result["runs"][0]["results"]
        assert len(results) == 1

        res = results[0]
        assert "locations" in res
        assert len(res["locations"]) == 1

        loc = res["locations"][0]
        assert "physicalLocation" in loc
        assert "artifactLocation" in loc["physicalLocation"]
        assert "region" in loc["physicalLocation"]

    def test_sarif_severity_score_mapping(self):
        """Security-severity scores should align with CVSS ranges."""
        formatter = SARIFFormatter()

        # Test all severity levels
        test_cases = [
            (Severity.CRITICAL, "9.8"),
            (Severity.HIGH, "7.5"),
            (Severity.MEDIUM, "5.0"),
            (Severity.LOW, "2.5"),
            (Severity.INFO, "0.0"),
        ]

        for severity, expected_score in test_cases:
            result = formatter.format([create_test_finding(severity=severity)])
            rule = result["runs"][0]["tool"]["driver"]["rules"][0]
            actual_score = rule["properties"]["security-severity"]
            assert actual_score == expected_score, (
                f"Severity {severity} should map to {expected_score}, got {actual_score}"
            )


class TestMimeTypeMapping:
    """Test MIME type detection for artifacts."""

    @pytest.mark.parametrize("file_path,expected_mime", [
        ("src/agent.py", "text/x-python"),
        ("app.js", "text/javascript"),
        ("config.json", "application/json"),
        ("deploy.yaml", "text/yaml"),
        ("README.md", "text/markdown"),
        ("unknown.xyz", "text/plain"),
    ])
    def test_mime_type_detection(self, file_path: str, expected_mime: str):
        """MIME types should be correctly detected from file extension."""
        assert _get_mime_type(file_path) == expected_mime
