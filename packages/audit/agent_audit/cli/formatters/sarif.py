"""SARIF 2.1.0 output formatter for GitHub Code Scanning."""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from agent_audit.models.finding import Finding
from agent_audit.models.risk import Severity
from agent_audit.version import __version__


# v0.15.0: MIME type mapping for artifacts
MIME_TYPE_MAP: Dict[str, str] = {
    ".py": "text/x-python",
    ".js": "text/javascript",
    ".ts": "text/typescript",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".sh": "text/x-shellscript",
    ".go": "text/x-go",
    ".rs": "text/x-rust",
    ".java": "text/x-java",
}


def _get_mime_type(file_path: str) -> str:
    """Get MIME type for a file based on extension."""
    ext = Path(file_path).suffix.lower()
    return MIME_TYPE_MAP.get(ext, "text/plain")


class SARIFFormatter:
    """
    SARIF 2.1.0 formatter for GitHub Code Scanning.

    Produces SARIF-compliant JSON output that can be uploaded to
    GitHub's code scanning feature.
    """

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"

    def __init__(self, tool_name: str = "agent-audit"):
        self.tool_name = tool_name

    def format(
        self,
        findings: List[Finding],
        scan_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Format findings as SARIF.

        Args:
            findings: List of findings to format
            scan_context: Optional context with scan metadata
                - command_line: CLI command used
                - start_time: Scan start time (ISO format)
                - end_time: Scan end time (ISO format)
                - scanned_files: List of scanned file paths

        Returns:
            SARIF document as dictionary
        """
        scan_context = scan_context or {}
        rules = self._extract_rules(findings)
        results = [self._finding_to_result(f) for f in findings]

        # v0.15.0: Build invocations section
        now = datetime.utcnow().isoformat() + "Z"
        invocations = [{
            "executionSuccessful": True,
            "commandLine": scan_context.get("command_line", f"{self.tool_name} scan"),
            "startTimeUtc": scan_context.get("start_time", now),
            "endTimeUtc": scan_context.get("end_time", now),
        }]

        # v0.15.0: Build artifacts section
        artifacts = self._build_artifacts(scan_context.get("scanned_files", []))

        run: Dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": __version__,
                    "informationUri": "https://github.com/anthropics/agent-audit",
                    "organization": "Agent Security Suite",
                    "rules": rules
                }
            },
            "invocations": invocations,
            "results": results
        }

        # Only add artifacts if we have scanned files
        if artifacts:
            run["artifacts"] = artifacts

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [run]
        }

    def _build_artifacts(self, scanned_files: List[str]) -> List[Dict[str, Any]]:
        """
        Build SARIF artifacts list from scanned files.

        v0.15.0: Added for SARIF completeness.

        Args:
            scanned_files: List of file paths that were scanned

        Returns:
            List of artifact dictionaries
        """
        # Limit to first 100 to avoid bloat
        artifacts = []
        for file_path in scanned_files[:100]:
            artifact: Dict[str, Any] = {
                "location": {"uri": file_path},
                "mimeType": _get_mime_type(file_path),
            }
            artifacts.append(artifact)
        return artifacts

    def format_to_string(self, findings: List[Finding], indent: int = 2) -> str:
        """Format findings as SARIF JSON string."""
        sarif = self.format(findings)
        return json.dumps(sarif, indent=indent)

    def save(self, findings: List[Finding], output_path: Path):
        """Save findings as SARIF file."""
        sarif_str = self.format_to_string(findings)
        output_path.write_text(sarif_str, encoding="utf-8")

    def _extract_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Extract unique rules from findings."""
        rules_map: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            if finding.rule_id not in rules_map:
                rule = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_level(finding.severity)
                    },
                    "properties": {
                        "security-severity": self._severity_to_score(finding.severity)
                    }
                }

                # Add help text if remediation available
                if finding.remediation:
                    rule["help"] = {
                        "text": finding.remediation.description,
                        "markdown": finding.remediation.description
                    }

                # Add CWE/OWASP tags
                tags: List[str] = []
                if finding.cwe_id:
                    tags.append(f"external/cwe/{finding.cwe_id.lower()}")
                if finding.owasp_id:
                    # Use OWASP-Agentic prefix for ASI-XX identifiers
                    if finding.owasp_id.startswith("ASI-"):
                        tags.append(f"OWASP-Agentic-{finding.owasp_id}")
                    else:
                        tags.append(f"external/owasp/{finding.owasp_id}")
                    # Also add owasp-agentic-id to properties
                    rule["properties"]["owasp-agentic-id"] = finding.owasp_id  # type: ignore[index]
                if finding.category:
                    tags.append(finding.category.value)
                if tags:
                    rule["properties"]["tags"] = tags  # type: ignore[index]

                rules_map[finding.rule_id] = rule

        return list(rules_map.values())

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        result = finding.to_sarif()

        # Add suppression info if suppressed
        if finding.suppressed:
            result["suppressions"] = [{
                "kind": "inSource" if "noaudit" in (finding.suppressed_reason or "") else "external",
                "justification": finding.suppressed_reason or "Suppressed by configuration"
            }]

        return result

    def _severity_to_level(self, severity: Severity) -> str:
        """Map severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping[severity]

    def _severity_to_score(self, severity: Severity) -> str:
        """
        Map severity to security-severity score (1.0-10.0).

        v0.15.0: Aligned with CVSS v3.1 severity ranges:
        - CRITICAL: 9.0-10.0
        - HIGH: 7.0-8.9
        - MEDIUM: 4.0-6.9
        - LOW: 0.1-3.9
        """
        mapping = {
            Severity.CRITICAL: "9.8",
            Severity.HIGH: "7.5",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "2.5",
            Severity.INFO: "0.0",
        }
        return mapping[severity]


def format_sarif(findings: List[Finding]) -> str:
    """Convenience function to format findings as SARIF."""
    formatter = SARIFFormatter()
    return formatter.format_to_string(findings)


def save_sarif(findings: List[Finding], output_path: Path):
    """Convenience function to save findings as SARIF."""
    formatter = SARIFFormatter()
    formatter.save(findings, output_path)
