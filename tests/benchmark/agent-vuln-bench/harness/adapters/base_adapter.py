"""
Base Adapter for Agent-Vuln-Bench Tool Integration.

This module defines the common interface for all SAST tool adapters,
enabling tool-agnostic evaluation in the benchmark harness.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ToolNotAvailable(Exception):
    """Raised when a tool is not installed or not accessible."""

    pass


@dataclass
class ToolFinding:
    """
    Tool-agnostic finding format.

    This standardized format allows comparison across different SAST tools
    by normalizing their outputs to a common schema.
    """

    # Core fields from tool output
    file: str
    line: int
    rule_id: str
    severity: str
    message: str
    confidence: float = 1.0
    tier: Optional[str] = None  # BLOCK | WARN | INFO | SUPPRESSED (v2)

    # Mapped fields for benchmark evaluation
    mapped_vuln_type: str = ""
    mapped_set: str = ""

    # Optional additional context
    end_line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    tool_specific: Dict[str, Any] = field(default_factory=dict)

    def matches_oracle(
        self,
        oracle_file: str,
        oracle_line: int,
        line_tolerance: int = 5,
    ) -> bool:
        """
        Check if this finding matches an oracle entry.

        Args:
            oracle_file: Expected file path from oracle.
            oracle_line: Expected line number from oracle.
            line_tolerance: Acceptable line number difference.

        Returns:
            True if this finding matches the oracle entry.
        """
        # File matching: our file should end with oracle's file path
        if not self.file.endswith(oracle_file):
            return False

        # Line matching with tolerance
        if abs(self.line - oracle_line) > line_tolerance:
            return False

        return True


class BaseAdapter(ABC):
    """
    Abstract base class for all tool adapters.

    Each tool adapter must implement methods to:
    1. Run the tool and capture output
    2. Parse output into standardized ToolFinding format
    3. Map findings to benchmark categories
    """

    @abstractmethod
    def scan(self, project_path: str) -> List[ToolFinding]:
        """
        Run the tool on a project and return standardized findings.

        Args:
            project_path: Path to the project/file to scan.

        Returns:
            List of ToolFinding objects.

        Raises:
            ToolNotAvailable: If the tool is not installed.
        """
        pass

    @abstractmethod
    def get_tool_name(self) -> str:
        """Return the name of the tool (e.g., 'agent-audit', 'bandit')."""
        pass

    @abstractmethod
    def get_tool_version(self) -> str:
        """Return the version of the tool."""
        pass

    def is_available(self) -> bool:
        """
        Check if the tool is available on the system.

        Returns:
            True if the tool can be executed.
        """
        try:
            self.get_tool_version()
            return True
        except Exception:
            return False


# Severity normalization mapping
SEVERITY_MAP = {
    # agent-audit severities
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    # Bandit severities
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    # Semgrep severities
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def normalize_severity(severity: str) -> str:
    """Normalize severity string to standard format."""
    return SEVERITY_MAP.get(severity, "MEDIUM")
