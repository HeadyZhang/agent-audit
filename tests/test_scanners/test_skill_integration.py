"""Integration tests for skill scanners scanning fixture directories end-to-end."""

from pathlib import Path

import pytest

from agent_audit.scanners.skill_meta_scanner import SkillMetaScanner
from agent_audit.scanners.skill_body_scanner import SkillBodyScanner


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "openclaw_skills"


class TestSkillScannerIntegration:
    """End-to-end tests combining both skill scanners on fixture directories."""

    def setup_method(self):
        self.meta_scanner = SkillMetaScanner()
        self.body_scanner = SkillBodyScanner()

    def _scan_all(self, path: Path):
        """Run both scanners and collect all findings."""
        findings = []
        for result in self.meta_scanner.scan(path):
            findings.extend(result.security_findings)
        for result in self.body_scanner.scan(path):
            findings.extend(result.security_findings)
        return findings

    def test_clean_skill_zero_findings(self):
        """Clean skill should have exactly 0 findings across both scanners."""
        findings = self._scan_all(FIXTURES_DIR / "clean_skill")
        assert len(findings) == 0

    def test_malicious_skill_all_seven_rules(self):
        """Malicious skill should trigger all 7 new rules."""
        findings = self._scan_all(FIXTURES_DIR / "malicious_skill")
        rule_ids = {f.rule_id for f in findings}
        assert "AGENT-058" in rule_ids, "Missing obfuscated shell detection"
        assert "AGENT-059" in rule_ids, "Missing critical file modification detection"
        assert "AGENT-060" in rule_ids, "Missing suspicious endpoint detection"
        assert "AGENT-061" in rule_ids, "Missing sandbox override detection"
        assert "AGENT-062" in rule_ids, "Missing fake dependency detection"
        assert "AGENT-063" in rule_ids, "Missing daemon persistence detection"
        assert "AGENT-064" in rule_ids, "Missing auto-invocation detection"

    def test_warn_skill_only_agent_060(self):
        """Warn skill should only trigger AGENT-060 (non-HTTPS endpoint)."""
        findings = self._scan_all(FIXTURES_DIR / "warn_skill")
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-060"

    def test_malicious_skill_finding_count(self):
        """Malicious skill should have at least 10 total findings."""
        findings = self._scan_all(FIXTURES_DIR / "malicious_skill")
        assert len(findings) >= 10, (
            f"Expected >= 10 findings, got {len(findings)}: "
            f"{[(f.rule_id, f.pattern_type) for f in findings]}"
        )

    def test_scan_entire_fixtures_directory(self):
        """Scanning the entire fixtures directory should find all SKILL.md files."""
        meta_results = self.meta_scanner.scan(FIXTURES_DIR)
        body_results = self.body_scanner.scan(FIXTURES_DIR)
        # Should find 3 SKILL.md files (clean, malicious, warn)
        assert len(meta_results) == 3
        assert len(body_results) == 3

    def test_all_findings_have_owasp_id(self):
        """Every finding should have an OWASP ID."""
        findings = self._scan_all(FIXTURES_DIR / "malicious_skill")
        for f in findings:
            assert f.owasp_id is not None, (
                f"Finding {f.rule_id}/{f.pattern_type} missing owasp_id"
            )

    def test_all_findings_have_positive_confidence(self):
        """Every finding should have a positive confidence score."""
        findings = self._scan_all(FIXTURES_DIR / "malicious_skill")
        for f in findings:
            assert f.confidence > 0.0, (
                f"Finding {f.rule_id} has zero confidence"
            )
            assert f.confidence <= 1.0, (
                f"Finding {f.rule_id} has confidence > 1.0: {f.confidence}"
            )
