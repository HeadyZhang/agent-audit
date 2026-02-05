"""
Bandit Adapter for Agent-Vuln-Bench.

Integrates Bandit Python SAST tool with the benchmark harness.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter, ToolFinding, ToolNotAvailable, normalize_severity


class BanditAdapter(BaseAdapter):
    """Adapter for Bandit Python security linter."""

    def __init__(self):
        self._version: Optional[str] = None

    def get_tool_name(self) -> str:
        return "bandit"

    def get_tool_version(self) -> str:
        if self._version is None:
            try:
                result = subprocess.run(
                    ["bandit", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout.strip()
                if output:
                    # Parse "bandit X.Y.Z"
                    parts = output.split()
                    self._version = parts[-1] if parts else "unknown"
                else:
                    raise ToolNotAvailable("bandit --version returned empty output")
            except FileNotFoundError:
                raise ToolNotAvailable("bandit not found. Install with: pip install bandit")
            except subprocess.TimeoutExpired:
                raise ToolNotAvailable("bandit --version timed out")
        return self._version

    def scan(self, project_path: str) -> List[ToolFinding]:
        """
        Run Bandit scan and return findings.

        Args:
            project_path: Path to scan (file or directory).

        Returns:
            List of standardized ToolFinding objects.
        """
        try:
            # Run bandit with JSON output
            # -r: recursive, -f json: JSON format, -ll: low severity and above
            result = subprocess.run(
                ["bandit", "-r", project_path, "-f", "json", "-ll"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Bandit returns non-zero exit code when findings exist
            # Parse JSON from stdout regardless of exit code
            output = result.stdout
            if not output:
                return []

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                return []

            raw_findings = data.get("results", [])
            return [self._convert_finding(f) for f in raw_findings]

        except subprocess.TimeoutExpired:
            raise ToolNotAvailable("bandit scan timed out after 300 seconds")
        except FileNotFoundError:
            raise ToolNotAvailable("bandit not found. Install with: pip install bandit")

    def _convert_finding(self, finding: Dict[str, Any]) -> ToolFinding:
        """Convert Bandit finding to standardized format."""
        # Map Bandit severity/confidence
        severity = normalize_severity(finding.get("issue_severity", "Medium"))

        # Map confidence to float
        confidence_map = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
        confidence = confidence_map.get(
            finding.get("issue_confidence", "MEDIUM"), 0.6
        )

        # Get rule ID (test_id like B102, B307)
        rule_id = finding.get("test_id", "unknown")

        # Map to benchmark categories
        mapped_type = self._map_bandit_rule(rule_id)
        mapped_set = self._map_bandit_set(rule_id)

        return ToolFinding(
            file=finding.get("filename", ""),
            line=finding.get("line_number", 0),
            rule_id=rule_id,
            severity=severity,
            message=finding.get("issue_text", ""),
            confidence=confidence,
            mapped_vuln_type=mapped_type,
            mapped_set=mapped_set,
            snippet=finding.get("code", ""),
            tool_specific={
                "test_name": finding.get("test_name", ""),
                "cwe": finding.get("issue_cwe", {}),
                "more_info": finding.get("more_info", ""),
            },
        )

    def _map_bandit_rule(self, test_id: str) -> str:
        """Map Bandit test ID to vulnerability type."""
        bandit_map = {
            # Code execution
            "B102": "exec",  # Use of exec
            "B307": "eval",  # Use of eval
            # Shell injection
            "B603": "subprocess_shell",  # subprocess with shell=True
            "B604": "shell_injection",  # Function call with shell=True
            "B605": "os_system",  # os.system
            "B607": "subprocess_popen",  # partial path in Popen
            # Credentials
            "B105": "hardcoded_password",  # hardcoded password string
            "B106": "hardcoded_password",  # hardcoded password argument
            "B107": "hardcoded_password",  # hardcoded password default
            # SSL/TLS
            "B501": "no_cert_validation",  # requests with verify=False
            "B502": "ssl_no_version",  # ssl.wrap_socket without version
            # Pickle
            "B301": "pickle_load",  # pickle.load
            # SQL injection
            "B608": "sql_injection",  # hardcoded SQL
            # YAML
            "B506": "yaml_load",  # yaml.load without Loader
        }
        return bandit_map.get(test_id, "other")

    def _map_bandit_set(self, test_id: str) -> str:
        """Map Bandit test ID to benchmark Set.

        Note: Bandit doesn't understand MCP or Agent-specific patterns,
        so Set B (MCP & Component) will be empty.
        """
        set_a_tests = {
            "B102",
            "B307",
            "B603",
            "B604",
            "B605",
            "B607",
        }  # Code/Command execution
        set_c_tests = {
            "B105",
            "B106",
            "B107",
            "B501",
            "B502",
            "B301",
            "B506",
            "B608",
        }  # Data/Auth

        if test_id in set_a_tests:
            return "A"
        elif test_id in set_c_tests:
            return "C"
        else:
            return ""  # Unknown or not applicable
