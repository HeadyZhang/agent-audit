"""Skill metadata scanner for SKILL.md YAML frontmatter security analysis."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

import yaml

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class SkillMetaFinding:
    """Security finding from skill metadata analysis."""

    rule_id: str
    pattern_type: str
    description: str
    severity: str
    confidence: float
    line: int = 1
    snippet: str = ""
    owasp_id: Optional[str] = None


@dataclass
class SkillMetaScanResult(ScanResult):
    """Result of skill metadata scanning."""

    skill_metadata: Dict[str, Any] = field(default_factory=dict)
    security_findings: List[SkillMetaFinding] = field(default_factory=list)


# Daemon/persistence keywords
_DAEMON_KEYWORDS_RE = re.compile(
    r"--install-daemon|launchd|systemd|launchctl|crontab|setsid|nohup",
    re.IGNORECASE,
)

# Standard safe ports for network endpoints
_SAFE_PORTS = {80, 443, 8080, 8443}

# Raw IP address pattern
_RAW_IP_RE = re.compile(
    r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
)


class SkillMetaScanner(BaseScanner):
    """
    Scanner for SKILL.md YAML frontmatter security patterns.

    Detects:
    - AGENT-063: Daemon persistence risk
    - AGENT-064: Auto-invocation without consent
    - AGENT-060: Suspicious network endpoints
    - AGENT-061: Sandbox override
    """

    name = "Skill Metadata Scanner"

    SKILL_FILENAMES = ["SKILL.md", "skill.md"]

    def scan(self, path: Path) -> List[SkillMetaScanResult]:
        """Scan for SKILL.md files and analyze frontmatter."""
        results: List[SkillMetaScanResult] = []
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

    def _scan_skill_file(self, file_path: Path) -> Optional[SkillMetaScanResult]:
        """Parse and analyze a single SKILL.md file."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Error reading %s: %s", file_path, exc)
            return None

        frontmatter, line_map = self._parse_frontmatter(content)
        if frontmatter is None:
            return SkillMetaScanResult(
                source_file=str(file_path),
                skill_metadata={},
                security_findings=[],
            )

        findings: List[SkillMetaFinding] = []
        findings.extend(self._check_daemon_persistence(frontmatter, file_path, line_map, content))
        findings.extend(self._check_always_true(frontmatter, file_path, line_map))
        findings.extend(self._check_suspicious_endpoints(frontmatter, file_path, line_map))
        findings.extend(self._check_sandbox_override(frontmatter, file_path, line_map))

        return SkillMetaScanResult(
            source_file=str(file_path),
            skill_metadata=frontmatter,
            security_findings=findings,
        )

    def _parse_frontmatter(self, content: str) -> tuple:
        """
        Parse YAML frontmatter between --- delimiters.

        Returns:
            (parsed_dict, line_map) or (None, {}) on failure.
            line_map maps top-level keys to approximate line numbers.
        """
        lines = content.split("\n")
        if not lines or lines[0].strip() != "---":
            return None, {}

        end_idx = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                end_idx = i
                break

        if end_idx is None:
            return None, {}

        yaml_text = "\n".join(lines[1:end_idx])
        try:
            parsed = yaml.safe_load(yaml_text)
        except yaml.YAMLError as exc:
            logger.warning("YAML parse error in frontmatter: %s", exc)
            return None, {}

        if not isinstance(parsed, dict):
            return None, {}

        # Build line_map: key -> 1-based line number
        line_map: Dict[str, int] = {}
        for idx, line in enumerate(lines[1:end_idx], start=2):
            stripped = line.lstrip()
            if stripped and not stripped.startswith("#") and ":" in stripped:
                key = stripped.split(":")[0].strip()
                if key not in line_map:
                    line_map[key] = idx

        return parsed, line_map

    def _get_openclaw_meta(self, frontmatter: Dict[str, Any]) -> Dict[str, Any]:
        """Extract openclaw metadata from nested or flat structure."""
        nested = (
            frontmatter.get("metadata", {}).get("openclaw", {})
        )
        if nested:
            return nested
        return frontmatter

    def _check_daemon_persistence(
        self,
        frontmatter: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int],
        content: str,
    ) -> List[SkillMetaFinding]:
        """AGENT-063: Detect daemon persistence risk."""
        findings: List[SkillMetaFinding] = []
        meta = self._get_openclaw_meta(frontmatter)

        # Check persistence: true
        if meta.get("persistence") is True:
            findings.append(SkillMetaFinding(
                rule_id="AGENT-063",
                pattern_type="skill_daemon_persistence",
                description=(
                    "Skill declares persistence: true, indicating it installs "
                    "a background daemon that runs outside the agent session"
                ),
                severity="high",
                confidence=0.90,
                line=line_map.get("persistence", 1),
                snippet="persistence: true",
                owasp_id="ASI-03",
            ))

        # Check description for daemon keywords
        description = frontmatter.get("description", "")
        if isinstance(description, str) and _DAEMON_KEYWORDS_RE.search(description):
            match = _DAEMON_KEYWORDS_RE.search(description)
            findings.append(SkillMetaFinding(
                rule_id="AGENT-063",
                pattern_type="skill_daemon_persistence",
                description=(
                    f"Skill description references daemon/service keyword: "
                    f"'{match.group()}'"
                ),
                severity="high",
                confidence=0.90,
                line=line_map.get("description", 1),
                snippet=description[:120],
                owasp_id="ASI-03",
            ))

        return findings

    def _check_always_true(
        self,
        frontmatter: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int],
    ) -> List[SkillMetaFinding]:
        """AGENT-064: Detect always: true auto-invocation."""
        findings: List[SkillMetaFinding] = []
        meta = self._get_openclaw_meta(frontmatter)

        if meta.get("always") is True:
            findings.append(SkillMetaFinding(
                rule_id="AGENT-064",
                pattern_type="skill_always_true_auto_invoke",
                description=(
                    "Skill declares always: true, meaning it auto-invokes on every "
                    "agent session without explicit user consent"
                ),
                severity="high",
                confidence=0.85,
                line=line_map.get("always", 1),
                snippet="always: true",
                owasp_id="ASI-09",
            ))

        return findings

    def _check_suspicious_endpoints(
        self,
        frontmatter: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int],
    ) -> List[SkillMetaFinding]:
        """AGENT-060: Detect suspicious network endpoints."""
        findings: List[SkillMetaFinding] = []
        meta = self._get_openclaw_meta(frontmatter)
        endpoints = meta.get("network_endpoints", [])

        if not isinstance(endpoints, list):
            return findings

        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if not url:
                continue

            # Raw IP address → 0.90
            if _RAW_IP_RE.match(url):
                findings.append(SkillMetaFinding(
                    rule_id="AGENT-060",
                    pattern_type="skill_suspicious_network_endpoint",
                    description=(
                        f"Network endpoint uses raw IP address: {url}. "
                        "This may indicate a command-and-control server."
                    ),
                    severity="high",
                    confidence=0.90,
                    line=line_map.get("network_endpoints", 1),
                    snippet=url,
                    owasp_id="ASI-04",
                ))
                continue

            # Non-HTTPS → 0.80
            if url.startswith("http://"):
                findings.append(SkillMetaFinding(
                    rule_id="AGENT-060",
                    pattern_type="skill_suspicious_network_endpoint",
                    description=(
                        f"Network endpoint uses unencrypted HTTP: {url}. "
                        "Use HTTPS for secure communication."
                    ),
                    severity="medium",
                    confidence=0.80,
                    line=line_map.get("network_endpoints", 1),
                    snippet=url,
                    owasp_id="ASI-04",
                ))
                continue

            # Unusual port → 0.70
            try:
                parsed = urlparse(url)
                if parsed.port and parsed.port not in _SAFE_PORTS:
                    findings.append(SkillMetaFinding(
                        rule_id="AGENT-060",
                        pattern_type="skill_suspicious_network_endpoint",
                        description=(
                            f"Network endpoint uses unusual port {parsed.port}: {url}. "
                            "Non-standard ports may indicate unauthorized services."
                        ),
                        severity="medium",
                        confidence=0.70,
                        line=line_map.get("network_endpoints", 1),
                        snippet=url,
                        owasp_id="ASI-04",
                    ))
            except Exception:
                pass

        return findings

    def _check_sandbox_override(
        self,
        frontmatter: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int],
    ) -> List[SkillMetaFinding]:
        """AGENT-061: Detect sandbox override."""
        findings: List[SkillMetaFinding] = []
        meta = self._get_openclaw_meta(frontmatter)

        if meta.get("sandbox") is False:
            findings.append(SkillMetaFinding(
                rule_id="AGENT-061",
                pattern_type="skill_sandbox_override",
                description=(
                    "Skill explicitly disables sandbox (sandbox: false). "
                    "This allows unrestricted code execution."
                ),
                severity="high",
                confidence=0.85,
                line=line_map.get("sandbox", 1),
                snippet="sandbox: false",
                owasp_id="ASI-05",
            ))

        return findings
