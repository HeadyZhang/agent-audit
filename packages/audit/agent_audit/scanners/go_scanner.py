"""
Go Security Scanner for agent-audit.

Provides regex-based security analysis for Go source files.
Detects common security issues in Go agent code without requiring
a Go toolchain installation.

Detected patterns:
- exec.Command / exec.CommandContext / syscall.Exec (AGENT-034)
- SQL string concatenation / fmt.Sprintf SQL (AGENT-041)
- math/rand without crypto/rand (AGENT-085)
- HTTP requests without TLS (AGENT-026)
- InsecureSkipVerify: true (AGENT-026)
- Unsafe deserialization via gob (AGENT-049)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from agent_audit.models.finding import Finding, Remediation, confidence_to_tier
from agent_audit.models.risk import Category, Location, Severity
from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class GoScanResult(ScanResult):
    """Result of Go file scanning."""

    findings: List[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GoPatternSpec:
    """Immutable specification for a single Go security pattern."""

    pattern: re.Pattern[str]
    rule_id: str
    title: str
    severity: Severity
    category: Category
    cwe_id: str
    confidence: float
    description: str
    remediation: str


GO_PATTERNS: Dict[str, GoPatternSpec] = {
    "exec_command": GoPatternSpec(
        pattern=re.compile(r"exec\.Command\s*\("),
        rule_id="AGENT-034",
        title="Shell Command Execution (Go)",
        severity=Severity.HIGH,
        category=Category.UNEXPECTED_CODE_EXECUTION,
        cwe_id="CWE-78",
        confidence=0.85,
        description="exec.Command() call without input validation",
        remediation="Validate and sanitize all inputs to exec.Command()",
    ),
    "exec_command_context": GoPatternSpec(
        pattern=re.compile(r"exec\.CommandContext\s*\("),
        rule_id="AGENT-034",
        title="Shell Command Execution with Context (Go)",
        severity=Severity.HIGH,
        category=Category.UNEXPECTED_CODE_EXECUTION,
        cwe_id="CWE-78",
        confidence=0.80,
        description="exec.CommandContext() call without input validation",
        remediation="Validate and sanitize all inputs to exec.CommandContext()",
    ),
    "os_exec": GoPatternSpec(
        pattern=re.compile(r"syscall\.Exec\s*\("),
        rule_id="AGENT-034",
        title="Direct Syscall Execution (Go)",
        severity=Severity.CRITICAL,
        category=Category.UNEXPECTED_CODE_EXECUTION,
        cwe_id="CWE-78",
        confidence=0.90,
        description="Direct syscall.Exec() invocation",
        remediation="Avoid direct syscall execution; use exec.Command with validation",
    ),
    "sql_string_concat": GoPatternSpec(
        pattern=re.compile(
            r"(?:db|tx)\.(?:Query|Exec|QueryRow|QueryContext|ExecContext)\s*\([^)]*\+"
        ),
        rule_id="AGENT-041",
        title="SQL String Concatenation (Go)",
        severity=Severity.HIGH,
        category=Category.TOOL_MISUSE,
        cwe_id="CWE-89",
        confidence=0.80,
        description="SQL query built with string concatenation",
        remediation="Use parameterized queries with ? placeholders",
    ),
    "sql_fmt_sprintf": GoPatternSpec(
        pattern=re.compile(
            r'fmt\.Sprintf\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)',
            re.IGNORECASE,
        ),
        rule_id="AGENT-041",
        title="SQL via fmt.Sprintf (Go)",
        severity=Severity.HIGH,
        category=Category.TOOL_MISUSE,
        cwe_id="CWE-89",
        confidence=0.85,
        description="SQL query built with fmt.Sprintf",
        remediation="Use parameterized queries instead of fmt.Sprintf for SQL",
    ),
    "weak_rand": GoPatternSpec(
        pattern=re.compile(r'"math/rand"'),
        rule_id="AGENT-085",
        title="Weak Random Number Generation (Go)",
        severity=Severity.MEDIUM,
        category=Category.CREDENTIAL_EXPOSURE,
        cwe_id="CWE-330",
        confidence=0.75,
        description=(
            "Using math/rand instead of crypto/rand for "
            "security-sensitive operations"
        ),
        remediation=(
            "Use crypto/rand for cryptographic or "
            "security-sensitive randomness"
        ),
    ),
    "http_no_tls": GoPatternSpec(
        pattern=re.compile(r'http\.Get\s*\(\s*"http://'),
        rule_id="AGENT-026",
        title="HTTP Request Without TLS (Go)",
        severity=Severity.MEDIUM,
        category=Category.TOOL_MISUSE,
        cwe_id="CWE-319",
        confidence=0.70,
        description="HTTP GET request to unencrypted endpoint",
        remediation="Use HTTPS endpoints for all network requests",
    ),
    "tls_skip_verify": GoPatternSpec(
        pattern=re.compile(r"InsecureSkipVerify\s*:\s*true"),
        rule_id="AGENT-026",
        title="TLS Certificate Verification Disabled (Go)",
        severity=Severity.HIGH,
        category=Category.TOOL_MISUSE,
        cwe_id="CWE-295",
        confidence=0.90,
        description="TLS certificate verification is disabled",
        remediation="Enable TLS certificate verification in production",
    ),
    "unsafe_deserialization": GoPatternSpec(
        pattern=re.compile(
            r"gob\.NewDecoder\s*\(|json\.Unmarshal\s*\([^,]*\buntrusted"
        ),
        rule_id="AGENT-049",
        title="Potential Unsafe Deserialization (Go)",
        severity=Severity.MEDIUM,
        category=Category.SUPPLY_CHAIN,
        cwe_id="CWE-502",
        confidence=0.65,
        description="Deserialization of potentially untrusted data",
        remediation="Validate and sanitize data before deserialization",
    ),
}

# Directories to skip during recursive file discovery
SKIP_DIRS = frozenset({"vendor", "node_modules", ".git", "testdata"})


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class GoScanner(BaseScanner):
    """Go source code security scanner (regex-based, no Go toolchain needed)."""

    name = "Go Scanner"

    def __init__(self, exclude_patterns: Optional[List[str]] = None) -> None:
        self._exclude_patterns: frozenset[str] = frozenset(
            exclude_patterns or []
        )

    # -- public API ----------------------------------------------------------

    def scan(self, path: Path) -> Sequence[GoScanResult]:
        """Scan Go files at *path* for security issues."""
        results: List[GoScanResult] = []

        for go_file in self._find_go_files(path):
            result = self._analyze_file(go_file)
            if result is not None and result.findings:
                results.append(result)

        return results

    def scan_and_convert(self, path: Path) -> List[Finding]:
        """Scan and return Finding objects directly."""
        findings: List[Finding] = []
        for result in self.scan(path):
            findings.extend(result.findings)
        return findings

    # -- private helpers -----------------------------------------------------

    def _find_go_files(self, path: Path) -> List[Path]:
        """Discover *.go files, excluding vendor / test-data directories."""
        if path.is_file():
            return [path] if path.suffix == ".go" else []

        go_files: List[Path] = []
        if path.is_dir():
            for candidate in path.rglob("*.go"):
                if any(skip in candidate.parts for skip in SKIP_DIRS):
                    continue
                go_files.append(candidate)

        return go_files

    def _analyze_file(self, go_file: Path) -> Optional[GoScanResult]:
        """Analyze a single Go source file."""
        try:
            content = go_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("Error reading %s: %s", go_file, exc)
            return None

        findings: List[Finding] = []
        lines = content.splitlines()
        is_test_file = go_file.name.endswith("_test.go")

        # Pre-scan: detect if crypto/rand is also imported
        has_crypto_rand = '"crypto/rand"' in content

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip empty lines and single-line comments
            if not stripped or stripped.startswith("//"):
                continue

            for pattern_name, spec in GO_PATTERNS.items():
                if not spec.pattern.search(line):
                    continue

                # Context-aware suppression: weak_rand + crypto/rand
                if pattern_name == "weak_rand" and has_crypto_rand:
                    continue

                # Skip import-only lines for non-import patterns
                if pattern_name != "weak_rand" and stripped.startswith('"'):
                    continue

                # Reduce confidence for test files
                confidence = spec.confidence
                if is_test_file:
                    confidence *= 0.25

                # Drop findings below the SUPPRESSED threshold
                if confidence < 0.20:
                    continue

                findings.append(
                    Finding(
                        rule_id=spec.rule_id,
                        title=spec.title,
                        description=spec.description,
                        severity=spec.severity,
                        category=spec.category,
                        location=Location(
                            file_path=str(go_file),
                            start_line=line_num,
                            end_line=line_num,
                            snippet=stripped[:200],
                        ),
                        cwe_id=spec.cwe_id,
                        confidence=confidence,
                        tier=confidence_to_tier(confidence),
                        remediation=Remediation(
                            description=spec.remediation,
                        ),
                    )
                )

        return GoScanResult(
            source_file=str(go_file),
            findings=findings,
        )
