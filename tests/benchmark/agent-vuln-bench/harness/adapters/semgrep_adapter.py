"""
Semgrep Adapter for Agent-Vuln-Bench.

Integrates Semgrep SAST tool with the benchmark harness.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter, ToolFinding, ToolNotAvailable, normalize_severity


class SemgrepAdapter(BaseAdapter):
    """Adapter for Semgrep multi-language SAST tool."""

    def __init__(self, config: str = "auto"):
        """
        Initialize the adapter.

        Args:
            config: Semgrep config to use ('auto', 'p/python', etc.)
        """
        self._version: Optional[str] = None
        self._config = config

    def get_tool_name(self) -> str:
        return "semgrep"

    def get_tool_version(self) -> str:
        if self._version is None:
            try:
                result = subprocess.run(
                    ["semgrep", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout.strip()
                if output:
                    self._version = output.split("\n")[0]
                else:
                    raise ToolNotAvailable("semgrep --version returned empty output")
            except FileNotFoundError:
                raise ToolNotAvailable("semgrep not found. Install with: pip install semgrep")
            except subprocess.TimeoutExpired:
                raise ToolNotAvailable("semgrep --version timed out")
        return self._version

    def scan(self, project_path: str) -> List[ToolFinding]:
        """
        Run Semgrep scan and return findings.

        Args:
            project_path: Path to scan (file or directory).

        Returns:
            List of standardized ToolFinding objects.
        """
        try:
            # Run semgrep with JSON output
            result = subprocess.run(
                [
                    "semgrep",
                    f"--config={self._config}",
                    "--json",
                    project_path,
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse JSON output
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
            raise ToolNotAvailable("semgrep scan timed out after 300 seconds")
        except FileNotFoundError:
            raise ToolNotAvailable("semgrep not found. Install with: pip install semgrep")

    def _convert_finding(self, finding: Dict[str, Any]) -> ToolFinding:
        """Convert Semgrep finding to standardized format."""
        # Extract location
        start = finding.get("start", {})
        end = finding.get("end", {})

        # Get severity from extra field
        extra = finding.get("extra", {})
        severity_str = extra.get("severity", "WARNING")
        severity = normalize_severity(severity_str)

        # Get rule ID (check_id)
        rule_id = finding.get("check_id", "unknown")

        # Map to benchmark categories
        mapped_type = self._map_semgrep_rule(rule_id)
        mapped_set = self._map_semgrep_set(rule_id)

        return ToolFinding(
            file=finding.get("path", ""),
            line=start.get("line", 0),
            rule_id=rule_id,
            severity=severity,
            message=extra.get("message", ""),
            confidence=0.7,  # Semgrep doesn't provide confidence, use default
            mapped_vuln_type=mapped_type,
            mapped_set=mapped_set,
            end_line=end.get("line"),
            column=start.get("col"),
            snippet=extra.get("lines", ""),
            tool_specific={
                "metadata": extra.get("metadata", {}),
                "fix": extra.get("fix", ""),
                "fix_regex": extra.get("fix_regex", {}),
            },
        )

    def _map_semgrep_rule(self, check_id: str) -> str:
        """Map Semgrep check_id to vulnerability type."""
        # Semgrep rule IDs are hierarchical, extract key patterns
        check_lower = check_id.lower()

        if "eval" in check_lower:
            return "eval"
        elif "exec" in check_lower:
            return "exec"
        elif "subprocess" in check_lower or "shell" in check_lower:
            return "shell_injection"
        elif "hardcode" in check_lower or "password" in check_lower:
            return "hardcoded_credential"
        elif "sql" in check_lower:
            return "sql_injection"
        elif "xss" in check_lower:
            return "xss"
        elif "ssrf" in check_lower:
            return "ssrf"
        elif "deserial" in check_lower or "pickle" in check_lower:
            return "deserialization"
        else:
            return "other"

    def _map_semgrep_set(self, check_id: str) -> str:
        """Map Semgrep check_id to benchmark Set.

        Note: Semgrep has limited awareness of MCP patterns.
        Set B coverage depends on custom rules.
        """
        check_lower = check_id.lower()

        # Set A: Injection & RCE
        set_a_patterns = ["eval", "exec", "subprocess", "shell", "command", "inject", "ssrf"]
        for pattern in set_a_patterns:
            if pattern in check_lower:
                return "A"

        # Set C: Data & Auth
        set_c_patterns = [
            "hardcode",
            "password",
            "credential",
            "secret",
            "token",
            "auth",
            "sql",
            "deserial",
            "pickle",
        ]
        for pattern in set_c_patterns:
            if pattern in check_lower:
                return "C"

        # Set B: MCP patterns (very limited in default Semgrep rules)
        set_b_patterns = ["mcp", "tool_use", "agent_config"]
        for pattern in set_b_patterns:
            if pattern in check_lower:
                return "B"

        return ""  # Unknown
