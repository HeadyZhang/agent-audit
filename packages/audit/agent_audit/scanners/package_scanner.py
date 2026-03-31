"""
Package Configuration and Source Map Leakage Scanner (AGENT-110, AGENT-111).

Detects information leakage through package distribution artifacts:
- AGENT-110: Source map and debug artifact leakage in published packages
- AGENT-111: Internal configuration and hostname exposure in source code

Supports: package.json, .npmignore, pyproject.toml, MANIFEST.in, .py, .ts files
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from agent_audit.models.finding import (
    Finding,
    Remediation,
    confidence_to_tier,
)
from agent_audit.models.risk import Category, Location, Severity
from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


# ─── Internal Hostname Patterns ──────────────────────────────────────

_INTERNAL_HOSTNAME_PATTERN = re.compile(
    r"""
    (?:https?://)?                          # optional scheme
    [\w.-]+\.                               # subdomain(s)
    (?:internal|corp|staging)               # internal TLD markers
    \.[\w.-]+                               # remaining domain parts
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ─── Debug Mode Default On Pattern ───────────────────────────────────

_DEBUG_MODE_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"^\s*DEBUG\s*=\s*True\b", re.MULTILINE),
        "DEBUG = True as default value",
        0.80,
    ),
    (
        re.compile(r"^\s*DEBUG\s*:\s*bool\s*=\s*True\b", re.MULTILINE),
        "DEBUG: bool = True as typed default",
        0.82,
    ),
]

# ─── Source Map File Patterns ─────────────────────────────────────────

_DANGEROUS_FILE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\.map$", re.IGNORECASE), "source map file (.map)"),
    (re.compile(r"\.pdb$", re.IGNORECASE), "debug symbols (.pdb)"),
    (re.compile(r"\.env$", re.IGNORECASE), "environment file (.env)"),
    (re.compile(r"\.env\.\w+$", re.IGNORECASE), "environment file (.env.*)"),
]

# Directories to skip during file scanning
_SKIP_DIRS: Set[str] = {
    ".git", "venv", ".venv", "__pycache__", "dist",
    "build", "node_modules", ".tox", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "egg-info",
}


@dataclass
class PackageFinding:
    """Internal finding from package scanner before conversion."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    owasp_id: str
    cwe_id: str
    line: int
    snippet: str
    confidence: float
    file_path: str
    pattern_type: str
    remediation_text: str


@dataclass
class PackageScanResult(ScanResult):
    """Result of package scanning."""

    findings: List[PackageFinding] = field(default_factory=list)


class PackageScanner(BaseScanner):
    """
    Scanner for package configuration and source leakage issues.

    Implements:
    - AGENT-110: Source map / debug artifact leakage in distribution
    - AGENT-111: Internal configuration and hostname exposure
    """

    name = "Package Scanner"

    SUPPORTED_EXTENSIONS: Set[str] = {".py", ".ts", ".js"}
    CONFIG_FILES: Set[str] = {"package.json", "pyproject.toml", "MANIFEST.in"}

    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        self.exclude_patterns = exclude_patterns or []

    def scan(self, path: Path) -> List[PackageScanResult]:
        """Scan the given path for package leakage issues."""
        results: List[PackageScanResult] = []

        if path.is_file():
            result = self._scan_single_file(path)
            if result is not None:
                results.append(result)
            return results

        config_files = self._find_config_files(path)
        source_files = self._find_source_files(path)

        for config_file in config_files:
            result = self._scan_single_file(config_file)
            if result is not None:
                results.append(result)

        for source_file in source_files:
            result = self._scan_single_file(source_file)
            if result is not None:
                results.append(result)

        # Check for missing .npmignore in npm projects
        npm_result = self._check_npmignore_missing(path)
        if npm_result is not None:
            results.append(npm_result)

        return results

    def scan_and_convert(self, path: Path) -> List[Finding]:
        """
        Scan and convert results to Finding objects.

        Args:
            path: File or directory to scan

        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        scan_results = self.scan(path)

        for result in scan_results:
            for pkg_finding in result.findings:
                finding = self._convert_to_finding(pkg_finding)
                findings.append(finding)

        return findings

    # ─── File Discovery ──────────────────────────────────────────────

    def _find_config_files(self, path: Path) -> List[Path]:
        """Find package configuration files under the given path."""
        found: List[Path] = []
        for name in self.CONFIG_FILES:
            for file_path in path.rglob(name):
                if not self._should_skip(file_path):
                    found.append(file_path)
        return sorted(found)

    def _find_source_files(self, path: Path) -> List[Path]:
        """Find source files to scan for internal hostnames and debug mode."""
        found: List[Path] = []
        for ext in self.SUPPORTED_EXTENSIONS:
            for file_path in path.rglob(f"*{ext}"):
                if not self._should_skip(file_path):
                    found.append(file_path)
        return sorted(found)

    def _should_skip(self, file_path: Path) -> bool:
        """Check if a file path should be skipped."""
        return any(part in _SKIP_DIRS for part in file_path.parts)

    # ─── Single File Dispatch ────────────────────────────────────────

    def _scan_single_file(self, file_path: Path) -> Optional[PackageScanResult]:
        """Dispatch scanning based on file type."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Error reading %s: %s", file_path, exc)
            return None

        findings: List[PackageFinding] = []

        if file_path.name == "package.json":
            findings.extend(self._scan_package_json(file_path, content))
        elif file_path.name == "pyproject.toml":
            findings.extend(self._scan_pyproject_toml(file_path, content))
        elif file_path.name == "MANIFEST.in":
            findings.extend(self._scan_manifest_in(file_path, content))
        elif file_path.suffix in self.SUPPORTED_EXTENSIONS:
            findings.extend(self._scan_source_file(file_path, content))

        if not findings:
            return None

        return PackageScanResult(
            source_file=str(file_path),
            findings=findings,
        )

    # ─── package.json Scanning ───────────────────────────────────────

    def _scan_package_json(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan package.json for source map leakage in files array."""
        findings: List[PackageFinding] = []

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.debug("Invalid JSON in %s: %s", file_path, exc)
            return findings

        files_array = data.get("files")
        if not isinstance(files_array, list):
            return findings

        lines = content.split("\n")

        for entry in files_array:
            if not isinstance(entry, str):
                continue

            for pattern, desc in _DANGEROUS_FILE_PATTERNS:
                if pattern.search(entry):
                    line_num = self._find_line_in_content(lines, entry)
                    findings.append(
                        PackageFinding(
                            rule_id="AGENT-110",
                            title="Source Map Leakage in Package",
                            description=(
                                f"Package files array includes {desc}: "
                                f"'{entry}' may expose internal source code"
                            ),
                            severity=Severity.MEDIUM,
                            category=Category.SUPPLY_CHAIN_AGENTIC,
                            owasp_id="ASI-04",
                            cwe_id="CWE-540",
                            line=line_num,
                            snippet=entry,
                            confidence=0.85,
                            file_path=str(file_path),
                            pattern_type="source_map_in_package",
                            remediation_text=(
                                "Remove debug artifacts from the 'files' array "
                                "in package.json. Add *.map, *.pdb, and .env "
                                "patterns to .npmignore."
                            ),
                        )
                    )
                    break  # One finding per entry is sufficient

        return findings

    # ─── .npmignore Check ────────────────────────────────────────────

    def _check_npmignore_missing(self, path: Path) -> Optional[PackageScanResult]:
        """Check for missing .npmignore in npm projects."""
        package_json = path / "package.json"
        npmignore = path / ".npmignore"

        if not package_json.exists():
            return None

        if npmignore.exists():
            return None

        finding = PackageFinding(
            rule_id="AGENT-110",
            title="Missing .npmignore in npm Project",
            description=(
                "No .npmignore file found in npm project root. "
                "Without .npmignore, source maps, debug symbols, "
                "and environment files may be included in published packages."
            ),
            severity=Severity.LOW,
            category=Category.SUPPLY_CHAIN_AGENTIC,
            owasp_id="ASI-04",
            cwe_id="CWE-540",
            line=1,
            snippet="",
            confidence=0.65,
            file_path=str(package_json),
            pattern_type="npmignore_missing",
            remediation_text=(
                "Create a .npmignore file and add patterns for "
                "*.map, *.pdb, .env, and other debug artifacts."
            ),
        )

        return PackageScanResult(
            source_file=str(package_json),
            findings=[finding],
        )

    # ─── pyproject.toml Scanning ─────────────────────────────────────

    def _scan_pyproject_toml(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan pyproject.toml for missing *.map exclude."""
        findings: List[PackageFinding] = []

        has_map_exclude = self._has_map_exclude_toml(content)
        if has_map_exclude:
            return findings

        # Check if the project has any build configuration
        has_build_config = (
            "[build-system]" in content
            or "[tool.setuptools]" in content
            or "[tool.poetry]" in content
        )
        if not has_build_config:
            return findings

        findings.append(
            PackageFinding(
                rule_id="AGENT-110",
                title="Debug Artifact Not Excluded from Distribution",
                description=(
                    "pyproject.toml does not exclude *.map files from "
                    "distribution. Source maps may leak internal code "
                    "structure in published packages."
                ),
                severity=Severity.LOW,
                category=Category.SUPPLY_CHAIN_AGENTIC,
                owasp_id="ASI-04",
                cwe_id="CWE-540",
                line=1,
                snippet="",
                confidence=0.60,
                file_path=str(file_path),
                pattern_type="debug_artifact_in_dist",
                remediation_text=(
                    "Add '*.map' to the exclude patterns in your build "
                    "tool configuration (e.g., [tool.setuptools.packages.find] "
                    "exclude or [tool.poetry] exclude)."
                ),
            )
        )

        return findings

    def _has_map_exclude_toml(self, content: str) -> bool:
        """Check if pyproject.toml has *.map exclusion."""
        exclude_pattern = re.compile(
            r"exclude\s*=\s*\[.*?\*\.map.*?\]",
            re.DOTALL | re.IGNORECASE,
        )
        if exclude_pattern.search(content):
            return True

        # Check for glob-style exclude entries
        line_pattern = re.compile(r'"\*\.map"|\'\*\.map\'')
        return bool(line_pattern.search(content))

    # ─── MANIFEST.in Scanning ────────────────────────────────────────

    def _scan_manifest_in(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan MANIFEST.in for missing *.map exclude."""
        findings: List[PackageFinding] = []

        has_map_exclude = self._has_map_exclude_manifest(content)
        if has_map_exclude:
            return findings

        # Only flag if MANIFEST.in exists (it implies manual dist config)
        findings.append(
            PackageFinding(
                rule_id="AGENT-110",
                title="Debug Artifact Not Excluded from Distribution",
                description=(
                    "MANIFEST.in does not exclude *.map files. "
                    "Source maps may be included in sdist/wheel."
                ),
                severity=Severity.LOW,
                category=Category.SUPPLY_CHAIN_AGENTIC,
                owasp_id="ASI-04",
                cwe_id="CWE-540",
                line=1,
                snippet="",
                confidence=0.60,
                file_path=str(file_path),
                pattern_type="debug_artifact_in_dist",
                remediation_text=(
                    "Add 'global-exclude *.map' to MANIFEST.in "
                    "to prevent source maps from being distributed."
                ),
            )
        )

        return findings

    def _has_map_exclude_manifest(self, content: str) -> bool:
        """Check if MANIFEST.in excludes *.map files."""
        exclude_pattern = re.compile(
            r"(?:global-exclude|exclude)\s+.*\*\.map",
            re.IGNORECASE,
        )
        return bool(exclude_pattern.search(content))

    # ─── Source File Scanning ────────────────────────────────────────

    def _scan_source_file(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan .py and .ts files for internal hostnames and debug mode."""
        findings: List[PackageFinding] = []

        findings.extend(self._check_internal_hostnames(file_path, content))

        if file_path.suffix == ".py":
            findings.extend(self._check_debug_mode(file_path, content))

        return findings

    def _check_internal_hostnames(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan for internal hostnames (*.internal.*, *.corp.*, *.staging.*)."""
        findings: List[PackageFinding] = []
        lines = content.split("\n")
        seen_lines: Dict[int, bool] = {}

        for i, line_text in enumerate(lines, start=1):
            # Skip comments
            stripped = line_text.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for match in _INTERNAL_HOSTNAME_PATTERN.finditer(line_text):
                if i in seen_lines:
                    continue
                seen_lines[i] = True

                hostname = match.group()
                findings.append(
                    PackageFinding(
                        rule_id="AGENT-111",
                        title="Internal Hostname Exposed in Code",
                        description=(
                            f"Internal hostname '{hostname}' found in source "
                            f"code. This may expose internal infrastructure "
                            f"details in published packages."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.CREDENTIAL_EXPOSURE,
                        owasp_id="ASI-04",
                        cwe_id="CWE-200",
                        line=i,
                        snippet=line_text.strip()[:120],
                        confidence=0.75,
                        file_path=str(file_path),
                        pattern_type="internal_hostname_in_code",
                        remediation_text=(
                            "Replace internal hostnames with environment "
                            "variables or configuration values. Use "
                            "os.environ.get() or a config loader."
                        ),
                    )
                )

        return findings

    def _check_debug_mode(
        self, file_path: Path, content: str
    ) -> List[PackageFinding]:
        """Scan .py files for DEBUG = True as default."""
        findings: List[PackageFinding] = []
        lines = content.split("\n")

        for pattern, desc, confidence in _DEBUG_MODE_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                findings.append(
                    PackageFinding(
                        rule_id="AGENT-111",
                        title="Debug Mode Enabled by Default",
                        description=(
                            f"{desc}. Debug mode may expose sensitive "
                            f"information, verbose error messages, or "
                            f"internal stack traces in production."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.CREDENTIAL_EXPOSURE,
                        owasp_id="ASI-04",
                        cwe_id="CWE-489",
                        line=line_num,
                        snippet=snippet[:120],
                        confidence=confidence,
                        file_path=str(file_path),
                        pattern_type="debug_mode_default_on",
                        remediation_text=(
                            "Set DEBUG = False as default and load the "
                            "value from an environment variable: "
                            "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'"
                        ),
                    )
                )
                break  # One finding per pattern is sufficient

        return findings

    # ─── Utility Methods ─────────────────────────────────────────────

    def _find_line_in_content(self, lines: List[str], target: str) -> int:
        """Find the 1-based line number containing the target string."""
        for i, line in enumerate(lines, start=1):
            if target in line:
                return i
        return 1

    # ─── Conversion to Finding Model ─────────────────────────────────

    def _convert_to_finding(self, pkg_finding: PackageFinding) -> Finding:
        """Convert PackageFinding to Finding model."""
        tier = confidence_to_tier(pkg_finding.confidence)

        return Finding(
            rule_id=pkg_finding.rule_id,
            title=pkg_finding.title,
            description=pkg_finding.description,
            severity=pkg_finding.severity,
            category=pkg_finding.category,
            location=Location(
                file_path=pkg_finding.file_path,
                start_line=pkg_finding.line,
                end_line=pkg_finding.line,
                snippet=pkg_finding.snippet,
            ),
            confidence=pkg_finding.confidence,
            tier=tier,
            cwe_id=pkg_finding.cwe_id,
            owasp_id=pkg_finding.owasp_id,
            remediation=Remediation(
                description=pkg_finding.remediation_text,
            ),
            metadata={
                "pattern_type": pkg_finding.pattern_type,
                "scanner": self.name,
            },
        )
