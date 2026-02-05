"""
Agent-Audit Adapter for Agent-Vuln-Bench.

Integrates agent-audit scanner with the benchmark harness.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .base_adapter import BaseAdapter, ToolFinding, ToolNotAvailable, normalize_severity


class AgentAuditAdapter(BaseAdapter):
    """Adapter for agent-audit SAST tool."""

    def __init__(self, rule_mapping_path: Optional[str] = None):
        """
        Initialize the adapter.

        Args:
            rule_mapping_path: Path to OWASP mapping YAML for rule-to-set mapping.
        """
        self._version: Optional[str] = None
        self._rule_to_set: Dict[str, str] = {}
        self._rule_to_type: Dict[str, str] = {}

        # Load rule mapping if available
        if rule_mapping_path and os.path.exists(rule_mapping_path):
            self._load_rule_mapping(rule_mapping_path)
        else:
            # Try default location
            default_path = Path(__file__).parent.parent.parent / "taxonomy" / "owasp_agentic_mapping.yaml"
            if default_path.exists():
                self._load_rule_mapping(str(default_path))

    def _load_rule_mapping(self, path: str) -> None:
        """Load rule-to-set mapping from YAML."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
                self._rule_to_set = data.get("rule_to_set_map", {})
        except Exception:
            pass

    def get_tool_name(self) -> str:
        return "agent-audit"

    def get_tool_version(self) -> str:
        if self._version is None:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "agent_audit", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                # Parse version from output
                output = result.stdout.strip() or result.stderr.strip()
                if output:
                    # Handle various version formats
                    self._version = output.split()[-1] if output else "unknown"
                else:
                    self._version = "unknown"
            except Exception as e:
                raise ToolNotAvailable(f"agent-audit not available: {e}")
        return self._version

    def scan(self, project_path: str) -> List[ToolFinding]:
        """
        Run agent-audit scan and return findings.

        Args:
            project_path: Path to scan (file or directory).

        Returns:
            List of standardized ToolFinding objects.
        """
        try:
            # Run agent-audit with JSON output
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_audit",
                    "scan",
                    project_path,
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse JSON output
            output = result.stdout
            if not output:
                # Check if it's in stderr
                if result.stderr and result.stderr.strip().startswith("{"):
                    output = result.stderr
                else:
                    return []

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                # Try to find JSON in output
                for line in output.split("\n"):
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            data = json.loads(line)
                            break
                        except json.JSONDecodeError:
                            continue
                else:
                    return []

            # Handle both list and dict with 'findings' key
            if isinstance(data, list):
                raw_findings = data
            elif isinstance(data, dict):
                raw_findings = data.get("findings", [])
            else:
                return []

            return [self._convert_finding(f) for f in raw_findings]

        except subprocess.TimeoutExpired:
            raise ToolNotAvailable("agent-audit scan timed out after 300 seconds")
        except FileNotFoundError:
            raise ToolNotAvailable("agent-audit not found in PATH")

    def _convert_finding(self, finding: Dict[str, Any]) -> ToolFinding:
        """Convert agent-audit finding to standardized format."""
        # Extract file path
        location = finding.get("location", {})
        file_path = location.get("file_path", finding.get("file", ""))

        # Extract line number
        line = location.get("start_line", finding.get("line", 0))
        if isinstance(line, str):
            line = int(line) if line.isdigit() else 0

        # Extract rule ID
        rule_id = finding.get("rule_id", finding.get("id", "unknown"))

        # Normalize severity
        severity = normalize_severity(finding.get("severity", "MEDIUM"))

        # Get confidence
        confidence = finding.get("confidence", 1.0)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except ValueError:
                confidence = 1.0

        # Get tier (v2: BLOCK | WARN | INFO | SUPPRESSED)
        tier = finding.get("tier", "WARN")
        if not isinstance(tier, str):
            tier = "WARN"

        # Map to benchmark categories
        mapped_set = self._rule_to_set.get(rule_id, "")
        mapped_type = self._map_rule_to_type(rule_id)

        return ToolFinding(
            file=file_path,
            line=line,
            rule_id=rule_id,
            severity=severity,
            message=finding.get("message", finding.get("title", "")),
            confidence=confidence,
            tier=tier,
            mapped_vuln_type=mapped_type,
            mapped_set=mapped_set,
            end_line=location.get("end_line"),
            snippet=location.get("snippet", ""),
            tool_specific={
                "owasp_id": finding.get("owasp_id", ""),
                "cwe_id": finding.get("cwe_id", ""),
                "needs_review": finding.get("needs_review", False),
            },
        )

    def _map_rule_to_type(self, rule_id: str) -> str:
        """Map rule ID to vulnerability type."""
        type_map = {
            "AGENT-004": "hardcoded_credential",
            "AGENT-010": "unsanitized_tool_args",
            "AGENT-011": "prompt_injection",
            "AGENT-026": "tool_input_unsanitized",
            "AGENT-027": "system_prompt_injectable",
            "AGENT-029": "mcp_overpermissive",
            "AGENT-030": "mcp_no_confirm",
            "AGENT-031": "mcp_wide_access",
            "AGENT-032": "mcp_no_tls",
            "AGENT-033": "mcp_env_exposed",
            "AGENT-034": "eval_exec",
            "AGENT-035": "unrestricted_file",
            "AGENT-036": "shell_injection",
            "AGENT-037": "ssrf",
            "AGENT-043": "daemon_privilege",
        }
        return type_map.get(rule_id, "other")
