"""Suppression and Baseline models (v0.15.0).

Provides formal dataclasses for:
- Individual suppression entries
- Baseline file structure
- Inline suppression comments
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

# Inline suppression patterns
# Supports: # agent-audit: ignore AGENT-004 -- reason
#           # agent-audit: ignore-next-line AGENT-001
#           # noaudit AGENT-004 reason
INLINE_IGNORE_PATTERN = re.compile(
    r'#\s*(?:agent-audit:\s*ignore(?:-next-line)?|noaudit)\s+'
    r'(?P<rule_id>AGENT-\d+)'
    r'(?:\s+(?:--?\s*)?(?P<reason>.+))?$',
    re.IGNORECASE
)

INLINE_IGNORE_NEXT_LINE_PATTERN = re.compile(
    r'#\s*agent-audit:\s*ignore-next-line\s+'
    r'(?P<rule_id>AGENT-\d+)'
    r'(?:\s+--?\s*(?P<reason>.+))?$',
    re.IGNORECASE
)


@dataclass
class Suppression:
    """
    Individual suppression entry.

    Represents a single finding that should be suppressed,
    either from a baseline file or inline comment.
    """
    rule_id: str
    file_path: str
    line: int
    fingerprint: str
    reason: str = ""
    expires: Optional[str] = None  # ISO date string
    approved_by: Optional[str] = None
    source: str = "baseline"  # "baseline", "inline", "config"

    def is_expired(self) -> bool:
        """Check if this suppression has expired."""
        if not self.expires:
            return False
        try:
            expiry_date = datetime.fromisoformat(self.expires.replace('Z', '+00:00'))
            return datetime.now(expiry_date.tzinfo) > expiry_date
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "file": self.file_path,
            "line": self.line,
            "fingerprint": self.fingerprint,
        }
        if self.reason:
            result["reason"] = self.reason
        if self.expires:
            result["expires"] = self.expires
        if self.approved_by:
            result["approved_by"] = self.approved_by
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Suppression":
        """Create from dictionary."""
        return cls(
            rule_id=data.get("rule_id", ""),
            file_path=data.get("file", ""),
            line=data.get("line", 0),
            fingerprint=data.get("fingerprint", ""),
            reason=data.get("reason", ""),
            expires=data.get("expires"),
            approved_by=data.get("approved_by"),
            source="baseline",
        )


@dataclass
class Baseline:
    """
    Baseline file structure.

    Stores suppressions for CI/CD workflows to distinguish
    between known issues and new findings.
    """
    version: str = "1"
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    tool_version: str = ""
    suppressions: List[Suppression] = field(default_factory=list)

    # Set of fingerprints for quick lookup
    _fingerprint_set: set = field(default_factory=set, repr=False)

    def __post_init__(self):
        """Build fingerprint set for quick lookup."""
        self._fingerprint_set = {s.fingerprint for s in self.suppressions}

    def add_suppression(self, suppression: Suppression) -> None:
        """Add a suppression to the baseline."""
        self.suppressions.append(suppression)
        self._fingerprint_set.add(suppression.fingerprint)

    def contains_fingerprint(self, fingerprint: str) -> bool:
        """Check if a fingerprint is in the baseline."""
        return fingerprint in self._fingerprint_set

    def get_suppression(self, fingerprint: str) -> Optional[Suppression]:
        """Get suppression by fingerprint."""
        for s in self.suppressions:
            if s.fingerprint == fingerprint:
                return s
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "suppressions": [s.to_dict() for s in self.suppressions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Baseline":
        """Create from dictionary."""
        suppressions = [
            Suppression.from_dict(s) for s in data.get("suppressions", [])
        ]
        baseline = cls(
            version=data.get("version", "1"),
            generated_at=data.get("generated_at", ""),
            tool_version=data.get("tool_version", ""),
            suppressions=suppressions,
        )
        return baseline

    @classmethod
    def from_fingerprints(cls, fingerprints: List[str], tool_version: str = "") -> "Baseline":
        """
        Create baseline from a list of fingerprints.

        v0.15.0: Backward compatible with legacy baseline format.
        """
        suppressions = [
            Suppression(
                rule_id="",
                file_path="",
                line=0,
                fingerprint=fp,
                source="baseline",
            )
            for fp in fingerprints
        ]
        return cls(
            tool_version=tool_version,
            suppressions=suppressions,
        )


@dataclass
class InlineSuppression:
    """
    Inline suppression comment parsed from source code.

    Supports formats:
    - # agent-audit: ignore AGENT-004 -- reason
    - # agent-audit: ignore-next-line AGENT-001
    - # noaudit AGENT-004 reason
    """
    rule_id: str
    reason: str = ""
    line: int = 0
    applies_to_next_line: bool = False

    @classmethod
    def parse_line(cls, line_content: str, line_number: int) -> Optional["InlineSuppression"]:
        """
        Parse an inline suppression comment from a source line.

        Args:
            line_content: Content of the source line
            line_number: Line number (1-indexed)

        Returns:
            InlineSuppression if found, None otherwise
        """
        # Check for ignore-next-line first (more specific)
        match = INLINE_IGNORE_NEXT_LINE_PATTERN.search(line_content)
        if match:
            return cls(
                rule_id=match.group("rule_id").upper(),
                reason=match.group("reason") or "",
                line=line_number,
                applies_to_next_line=True,
            )

        # Check for regular ignore
        match = INLINE_IGNORE_PATTERN.search(line_content)
        if match:
            applies_next = "ignore-next-line" in line_content.lower()
            return cls(
                rule_id=match.group("rule_id").upper(),
                reason=match.group("reason") or "",
                line=line_number,
                applies_to_next_line=applies_next,
            )

        return None


def compute_finding_fingerprint(
    rule_id: str,
    file_path: str,
    start_line: int,
    snippet: str = ""
) -> str:
    """
    Compute a stable fingerprint for a finding.

    The fingerprint is used for baseline comparison.
    It's stable across reruns for the same issue.

    Args:
        rule_id: Rule identifier (e.g., "AGENT-001")
        file_path: Path to the file
        start_line: Starting line number
        snippet: Code snippet (first 50 chars used)

    Returns:
        16-character hex fingerprint
    """
    components = [
        rule_id,
        file_path,
        str(start_line),
        (snippet or "")[:50]
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_inline_suppressions(source_code: str) -> Dict[int, InlineSuppression]:
    """
    Parse all inline suppression comments from source code.

    Args:
        source_code: Full source code content

    Returns:
        Dict mapping line numbers to InlineSuppression objects.
        For ignore-next-line comments, the key is the NEXT line number.
    """
    suppressions: Dict[int, InlineSuppression] = {}
    lines = source_code.split('\n')

    for i, line in enumerate(lines):
        line_number = i + 1  # 1-indexed
        suppression = InlineSuppression.parse_line(line, line_number)

        if suppression:
            if suppression.applies_to_next_line:
                # Suppression applies to the next line
                suppressions[line_number + 1] = suppression
            else:
                # Suppression applies to current line
                suppressions[line_number] = suppression

    return suppressions
