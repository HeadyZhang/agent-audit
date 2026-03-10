"""Skill body scanner for SKILL.md markdown content security analysis."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class SkillBodyFinding:
    """Security finding from skill body analysis."""

    rule_id: str
    pattern_type: str
    description: str
    severity: str
    confidence: float
    line: int = 1
    snippet: str = ""
    owasp_id: Optional[str] = None


@dataclass
class SkillBodyScanResult(ScanResult):
    """Result of skill body scanning."""

    security_findings: List[SkillBodyFinding] = field(default_factory=list)


# ─── AGENT-058: Obfuscated Shell Command Patterns ─────────────────────

_OBFUSCATED_SHELL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # base64 decode piped to shell
    (
        re.compile(
            r"base64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
            re.IGNORECASE,
        ),
        "base64 decode piped to shell interpreter",
        0.95,
    ),
    # echo base64 payload piped to decode
    (
        re.compile(
            r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(?:-d|--decode)",
            re.IGNORECASE,
        ),
        "encoded payload piped to base64 decode",
        0.95,
    ),
    # curl piped to shell
    (
        re.compile(
            r"curl\s+[^\|]+\|\s*(?:sh|bash|dash|zsh|ksh)\b",
            re.IGNORECASE,
        ),
        "curl output piped to shell interpreter",
        0.92,
    ),
    # wget piped to shell
    (
        re.compile(
            r"wget\s+[^\|]+-O\s*-\s*\|\s*(?:sh|bash)",
            re.IGNORECASE,
        ),
        "wget output piped to shell interpreter",
        0.92,
    ),
    # eval with command substitution
    (
        re.compile(
            r"eval\s+\$\(|eval\s*\(\s*\$\(",
            re.IGNORECASE,
        ),
        "eval with command substitution",
        0.90,
    ),
    # python -c base64 inline execution
    (
        re.compile(
            r"python3?\s+-c\s+['\"]import\s+base64",
            re.IGNORECASE,
        ),
        "inline Python base64 decode execution",
        0.92,
    ),
    # hex-encoded payload (10+ hex escape sequences)
    (
        re.compile(
            r"(?:\\x[0-9a-fA-F]{2}){10,}",
        ),
        "hex-encoded payload",
        0.88,
    ),
    # powershell encoded command
    (
        re.compile(
            r"powershell\s+(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
        "PowerShell encoded command",
        0.95,
    ),
]


# ─── AGENT-059: Critical File Modification Patterns ───────────────────

_CRITICAL_FILES = (
    r"(?:SOUL\.md|AGENTS\.md|MEMORY\.md|IDENTITY\.md|TOOLS\.md|"
    r"\.agent-audit\.yaml)"
)

_CRITICAL_FILE_MOD_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # Natural language instructions to modify critical files
    (
        re.compile(
            r"(?:write|modify|overwrite|append|replace|update|edit|change|"
            r"add\s+to|insert\s+into)\s+.{0,40}" + _CRITICAL_FILES,
            re.IGNORECASE,
        ),
        "instruction to modify critical identity file",
        0.88,
    ),
    # Shell commands targeting critical files
    (
        re.compile(
            r"(?:cat|echo|printf|tee)\s+.*?(?:>|>>)\s*.*?" + _CRITICAL_FILES,
            re.IGNORECASE,
        ),
        "shell command writing to critical identity file",
        0.90,
    ),
    # Python open() writing to critical files
    (
        re.compile(
            r"open\s*\([^)]*" + _CRITICAL_FILES + r"[^)]*,\s*['\"]w",
            re.IGNORECASE,
        ),
        "Python code writing to critical identity file",
        0.90,
    ),
]


# ─── AGENT-062: Fake Dependency Patterns ──────────────────────────────

_FAKE_DEPENDENCY_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # npm install with suspicious package names
    (
        re.compile(
            r"npm\s+install\s+(?:-g\s+)?(?!@types/|@modelcontextprotocol/)"
            r"[a-z][\w-]*(?:[-_](?:core|utils|helper|lib|sdk|cli|api|runtime|"
            r"agent|claw|openclaw))",
            re.IGNORECASE,
        ),
        "potentially typosquatted npm package",
        0.65,
    ),
    # pip install with suspicious package names
    (
        re.compile(
            r"pip3?\s+install\s+(?!agent-audit\b)[a-z][\w-]*(?:[-_](?:core|utils|"
            r"helper|lib|sdk|cli|api|runtime|agent|claw|openclaw))",
            re.IGNORECASE,
        ),
        "potentially typosquatted pip package",
        0.65,
    ),
    # Deceptive markdown links (click here, this link, download)
    (
        re.compile(
            r"\[(?:click\s+here|this\s+link|download|install|get\s+it)\]"
            r"\(https?://(?!github\.com|pypi\.org|npmjs\.com|"
            r"docs\.python\.org|nodejs\.org)[^\)]+\)",
            re.IGNORECASE,
        ),
        "deceptive link to non-trusted domain",
        0.80,
    ),
    # Required/necessary dependency with URL
    (
        re.compile(
            r"(?:install|download|run|execute)\s+.{0,20}"
            r"(?:required|necessary|prerequisite|dependency)\s+.{0,40}"
            r"https?://(?!github\.com|pypi\.org|npmjs\.com)[^\s]+",
            re.IGNORECASE,
        ),
        "social engineering: fake required dependency with URL",
        0.75,
    ),
]


class SkillBodyScanner(BaseScanner):
    """
    Scanner for SKILL.md markdown body content.

    Detects:
    - AGENT-058: Obfuscated shell commands
    - AGENT-059: Critical file modification instructions
    - AGENT-062: Fake dependency social engineering
    """

    name = "Skill Body Scanner"

    SKILL_FILENAMES = ["SKILL.md", "skill.md"]

    def scan(self, path: Path) -> List[SkillBodyScanResult]:
        """Scan for SKILL.md files and analyze body content."""
        results: List[SkillBodyScanResult] = []
        skill_files = self._find_skill_files(path)

        for skill_file in skill_files:
            result = self._scan_skill_file(skill_file)
            if result:
                results.append(result)

        return results

    def _find_skill_files(self, path: Path) -> List[Path]:
        """Find SKILL.md files under the given path."""
        if path.is_file():
            if path.name in self.SKILL_FILENAMES:
                return [path]
            return []

        found: List[Path] = []
        seen_resolved: set = set()
        for name in self.SKILL_FILENAMES:
            for p in path.rglob(name):
                resolved = str(p.resolve()).lower()
                if resolved not in seen_resolved:
                    seen_resolved.add(resolved)
                    found.append(p)
        return sorted(found)

    def _scan_skill_file(self, file_path: Path) -> Optional[SkillBodyScanResult]:
        """Analyze a single SKILL.md file body."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Error reading %s: %s", file_path, exc)
            return None

        body, body_offset = self._extract_body(content)
        if not body:
            return SkillBodyScanResult(
                source_file=str(file_path),
                security_findings=[],
            )

        findings: List[SkillBodyFinding] = []
        findings.extend(
            self._check_obfuscated_shell(body, file_path, body_offset)
        )
        findings.extend(
            self._check_critical_file_modification(body, file_path, body_offset)
        )
        findings.extend(
            self._check_fake_dependency(body, file_path, body_offset)
        )

        return SkillBodyScanResult(
            source_file=str(file_path),
            security_findings=findings,
        )

    def _extract_body(self, content: str) -> Tuple[str, int]:
        """
        Extract body content after YAML frontmatter.

        Returns:
            (body_text, line_offset) where line_offset is the 1-based line
            number where the body begins.
        """
        lines = content.split("\n")
        if not lines or lines[0].strip() != "---":
            # No frontmatter — entire content is body
            return content, 1

        end_idx = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                end_idx = i
                break

        if end_idx is None:
            return "", 0

        body_start = end_idx + 1
        body = "\n".join(lines[body_start:])
        return body, body_start + 1  # 1-based

    def _line_number_in_body(self, body: str, match_start: int, offset: int) -> int:
        """Calculate the 1-based line number for a match position in the body."""
        return offset + body[:match_start].count("\n")

    def _check_obfuscated_shell(
        self,
        body: str,
        file_path: Path,
        offset: int,
    ) -> List[SkillBodyFinding]:
        """AGENT-058: Detect obfuscated shell commands."""
        findings: List[SkillBodyFinding] = []
        seen_lines: Dict[int, float] = {}  # line -> best confidence (dedup)

        for pattern, desc, confidence in _OBFUSCATED_SHELL_PATTERNS:
            for match in pattern.finditer(body):
                line = self._line_number_in_body(body, match.start(), offset)
                # Dedup: same line, same pattern type — keep highest confidence
                if line in seen_lines and seen_lines[line] >= confidence:
                    continue
                seen_lines[line] = confidence

                snippet = match.group()[:120]
                findings.append(SkillBodyFinding(
                    rule_id="AGENT-058",
                    pattern_type="skill_obfuscated_shell",
                    description=(
                        f"Obfuscated shell command detected: {desc}"
                    ),
                    severity="critical",
                    confidence=confidence,
                    line=line,
                    snippet=snippet,
                    owasp_id="ASI-04",
                ))

        return findings

    def _check_critical_file_modification(
        self,
        body: str,
        file_path: Path,
        offset: int,
    ) -> List[SkillBodyFinding]:
        """AGENT-059: Detect instructions to modify critical identity files."""
        findings: List[SkillBodyFinding] = []
        seen_lines: Dict[int, float] = {}

        for pattern, desc, confidence in _CRITICAL_FILE_MOD_PATTERNS:
            for match in pattern.finditer(body):
                line = self._line_number_in_body(body, match.start(), offset)
                if line in seen_lines and seen_lines[line] >= confidence:
                    continue
                seen_lines[line] = confidence

                snippet = match.group()[:120]
                findings.append(SkillBodyFinding(
                    rule_id="AGENT-059",
                    pattern_type="skill_critical_file_modification",
                    description=(
                        f"Critical file modification detected: {desc}"
                    ),
                    severity="high",
                    confidence=confidence,
                    line=line,
                    snippet=snippet,
                    owasp_id="ASI-01",
                ))

        return findings

    def _check_fake_dependency(
        self,
        body: str,
        file_path: Path,
        offset: int,
    ) -> List[SkillBodyFinding]:
        """AGENT-062: Detect fake dependency social engineering."""
        findings: List[SkillBodyFinding] = []
        seen_lines: Dict[int, float] = {}

        for pattern, desc, confidence in _FAKE_DEPENDENCY_PATTERNS:
            for match in pattern.finditer(body):
                line = self._line_number_in_body(body, match.start(), offset)
                if line in seen_lines and seen_lines[line] >= confidence:
                    continue
                seen_lines[line] = confidence

                snippet = match.group()[:120]
                findings.append(SkillBodyFinding(
                    rule_id="AGENT-062",
                    pattern_type="skill_fake_dependency",
                    description=(
                        f"Potential fake dependency: {desc}"
                    ),
                    severity="medium",
                    confidence=confidence,
                    line=line,
                    snippet=snippet,
                    owasp_id="ASI-04",
                ))

        return findings
