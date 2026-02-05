"""Tests for v0.5.2 micro-patch changes.

This module tests:
- AGENT-043 tightened daemon detection (excludes pkill/kill/nohup/&)
- AGENT-046 credential store deduplication
- AGENT-047 extended safe command list
- Risk Score v2 formula (smoother logarithmic scaling)
"""

import math
import pytest
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from agent_audit.scanners.privilege_scanner import PrivilegeScanner
from agent_audit.cli.formatters.terminal import (
    calculate_risk_score,
    deduplicate_credential_store_findings,
    finalize_findings,
)
from agent_audit.models.finding import Finding
from agent_audit.models.risk import Location, Severity, Category


def make_finding(
    rule_id: str,
    file_path: str = "test.ts",
    line: int = 1,
    conf: float = 0.75,
    tier: str = "WARN",
    severity: str = "high",
    snippet: str = "",
    description: str = "",
) -> Finding:
    """Helper to create Finding objects for testing."""
    return Finding(
        rule_id=rule_id,
        title=f"Test {rule_id}",
        description=description or f"Test finding for {rule_id}",
        severity=Severity(severity),
        category=Category.IDENTITY_PRIVILEGE_ABUSE,
        location=Location(
            file_path=file_path,
            start_line=line,
            end_line=line,
            snippet=snippet,
        ),
        confidence=conf,
        tier=tier,
        cwe_id="CWE-000",
    )


class TestAGENT043Tightened:
    """AGENT-043 daemon detection tightening tests."""

    @pytest.fixture
    def scanner(self):
        return PrivilegeScanner()

    def test_pkill_not_daemon(self, scanner, tmp_path):
        """pkill is killing processes, not daemon registration."""
        code = '''#!/bin/bash
pkill -f "gateway-daemon"
pkill -9 myapp
'''
        file_path = tmp_path / "restart.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0, f"pkill should not trigger daemon detection, got {len(f043)}"

    def test_kill_signal_not_daemon(self, scanner, tmp_path):
        """kill -9 is not daemon registration."""
        code = '''#!/bin/bash
kill -9 $PID
kill $GATEWAY_PID
'''
        file_path = tmp_path / "cleanup.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0

    def test_background_ampersand_not_daemon(self, scanner, tmp_path):
        """& background execution is not daemon registration."""
        code = '''#!/bin/bash
node server.js &
python worker.py &
'''
        file_path = tmp_path / "start.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0

    def test_nohup_not_daemon(self, scanner, tmp_path):
        """nohup is temporary background, not persistent daemon."""
        code = '''#!/bin/bash
nohup python worker.py &
nohup ./myapp > /dev/null 2>&1 &
'''
        file_path = tmp_path / "run.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0

    def test_real_launchctl_still_detected(self, scanner, tmp_path):
        """Real launchctl bootstrap/load should still be detected."""
        code = '''#!/bin/bash
launchctl bootstrap system /Library/LaunchDaemons/com.app.plist
'''
        file_path = tmp_path / "install.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1, "launchctl bootstrap should be detected"
        assert f043[0].confidence >= 0.75

    def test_real_systemctl_enable_still_detected(self, scanner, tmp_path):
        """systemctl enable should still be detected."""
        code = '''#!/bin/bash
systemctl enable myapp.service
'''
        file_path = tmp_path / "setup.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1

    def test_pm2_startup_still_detected(self, scanner, tmp_path):
        """pm2 startup (persistence) should still be detected."""
        code = '''#!/bin/bash
pm2 start app.js
pm2 save
pm2 startup
'''
        file_path = tmp_path / "deploy.sh"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1

    def test_docs_path_downgraded_to_info(self, scanner, tmp_path):
        """Daemon setup commands in docs/ are downgraded to INFO tier."""
        docs_dir = tmp_path / "docs" / "platforms"
        docs_dir.mkdir(parents=True)
        file_path = docs_dir / "raspberry-pi.md"
        file_path.write_text("""
# Raspberry Pi Setup
To enable openclaw as a service:
```bash
sudo systemctl enable openclaw
sudo systemctl start openclaw
```
""")
        results = scanner.scan(tmp_path)
        findings = []
        for r in results:
            findings.extend(r.findings)
        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1, "Should detect daemon pattern in docs"
        # Docs path should be downgraded: confidence 0.35 -> INFO tier
        assert f043[0].confidence == 0.35
        assert f043[0].severity.value == "info"

    def test_src_daemon_keeps_warn_tier(self, scanner, tmp_path):
        """Daemon code in src/ keeps WARN tier."""
        src_dir = tmp_path / "src" / "daemon"
        src_dir.mkdir(parents=True)
        file_path = src_dir / "launchd.ts"
        file_path.write_text('throw new Error(`launchctl bootstrap failed: ${boot.stderr}`);')
        results = scanner.scan(tmp_path)
        findings = []
        for r in results:
            findings.extend(r.findings)
        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1
        assert f043[0].confidence >= 0.60, "src/ daemon should stay WARN tier"


class TestAGENT046Dedup:
    """AGENT-046 credential store deduplication tests."""

    def test_multiple_keychain_calls_deduped(self):
        """Same keychain type called 5 times -> only 1 finding."""
        findings_input = [
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85,
                        snippet="security find-generic-password -s app"),
            make_finding("AGENT-046", "utils.ts", 12, conf=0.80,
                        snippet="security find-generic-password -s other"),
            make_finding("AGENT-046", "debug.ts", 30, conf=0.75,
                        snippet="readKeychainPassword(service)"),
            make_finding("AGENT-046", "test.ts", 8, conf=0.70,
                        snippet="security find-generic-password -s test"),
            make_finding("AGENT-046", "init.ts", 3, conf=0.65,
                        snippet="security find-internet-password"),
        ]
        result = deduplicate_credential_store_findings(findings_input)
        f046 = [f for f in result if f.rule_id == "AGENT-046"]
        assert len(f046) == 1, f"Should dedup to 1, got {len(f046)}"
        assert f046[0].confidence == 0.85  # Keep highest confidence

    def test_different_store_types_preserved(self):
        """Different credential store types should each be preserved."""
        findings_input = [
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85,
                        snippet="security find-generic-password"),  # keychain
            make_finding("AGENT-046", "config.ts", 8, conf=0.75,
                        snippet="rbw get mypassword"),  # bitwarden
        ]
        result = deduplicate_credential_store_findings(findings_input)
        f046 = [f for f in result if f.rule_id == "AGENT-046"]
        assert len(f046) == 2, "Different store types should be preserved"

    def test_other_rules_not_affected(self):
        """Other rules should not be affected by AGENT-046 dedup."""
        findings_input = [
            make_finding("AGENT-004", "config.md", 10, conf=0.78),
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85,
                        snippet="security find-generic-password"),
            make_finding("AGENT-046", "utils.ts", 12, conf=0.80,
                        snippet="security find-generic-password"),
            make_finding("AGENT-044", "setup.sh", 3, conf=0.90),
        ]
        result = deduplicate_credential_store_findings(findings_input)
        assert len([f for f in result if f.rule_id == "AGENT-004"]) == 1
        assert len([f for f in result if f.rule_id == "AGENT-044"]) == 1
        assert len([f for f in result if f.rule_id == "AGENT-046"]) == 1


class TestAGENT047ExtendedSafe:
    """AGENT-047 extended safe command list tests."""

    @pytest.fixture
    def scanner(self):
        return PrivilegeScanner()

    def test_open_command_lowered(self, scanner, tmp_path):
        """macOS open command should be lowered."""
        code = '''
import { execSync } from "child_process";
execSync("open https://example.com");
'''
        file_path = tmp_path / "utils.ts"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047), \
                f"open command should have low confidence, got {[f.confidence for f in f047]}"

    def test_pbcopy_lowered(self, scanner, tmp_path):
        """pbcopy clipboard command should be lowered."""
        code = '''
import { spawn } from "child_process";
spawn("pbcopy", [], { input: text });
'''
        file_path = tmp_path / "clipboard.ts"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)

    def test_grep_lowered(self, scanner, tmp_path):
        """grep text search should be lowered."""
        code = '''
import { execSync } from "child_process";
execSync("grep -r pattern .");
'''
        file_path = tmp_path / "search.ts"
        file_path.write_text(code)

        results = scanner.scan(file_path)
        findings = []
        for r in results:
            findings.extend(r.findings)

        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)


class TestRiskScoreV2:
    """Risk Score v2 formula tests."""

    def test_zero_findings(self):
        """Zero findings should give 0.0 score."""
        assert calculate_risk_score([]) == 0.0

    def test_small_project(self):
        """3 WARN findings -> 2.0-4.5 range."""
        findings = [make_finding("AGENT-004", conf=0.75, tier="WARN")] * 3
        score = calculate_risk_score(findings)
        assert 2.0 <= score <= 4.5, f"Small project score {score} out of range"

    def test_medium_project(self):
        """10 WARN findings -> 4.0-7.0 range."""
        findings = [make_finding("AGENT-047", conf=0.75, tier="WARN")] * 10
        score = calculate_risk_score(findings)
        assert 4.0 <= score <= 7.0, f"Medium project score {score} out of range"

    def test_openclaw_range(self):
        """~20 WARN findings -> 5.0-8.0 (openclaw v0.5.2 expected)."""
        findings = [make_finding("AGENT-047", conf=0.78, tier="WARN")] * 20
        score = calculate_risk_score(findings)
        assert 5.0 <= score <= 8.0, f"openclaw-like score {score} out of range"

    def test_extreme_project(self):
        """50 WARN + 5 BLOCK -> 8.0-9.8 range."""
        findings = (
            [make_finding("AGENT-047", conf=0.80, tier="WARN", severity="high")] * 50 +
            [make_finding("AGENT-004", conf=0.95, tier="BLOCK", severity="critical")] * 5
        )
        score = calculate_risk_score(findings)
        assert 8.0 <= score <= 9.8, f"Extreme project score {score} out of range"

    def test_never_reaches_10(self):
        """Even 100 BLOCK findings should not reach 10.0."""
        findings = [make_finding("AGENT-004", conf=1.0, tier="BLOCK", severity="critical")] * 100
        score = calculate_risk_score(findings)
        assert score <= 9.8, f"Score {score} should be capped at 9.8"

    def test_info_suppressed_not_counted(self):
        """INFO and SUPPRESSED should not count toward Risk Score."""
        findings = [
            make_finding("AGENT-004", conf=0.90, tier="BLOCK"),
            make_finding("AGENT-047", conf=0.40, tier="INFO"),
            make_finding("AGENT-004", conf=0.15, tier="SUPPRESSED"),
        ]
        score = calculate_risk_score(findings)
        # Only the BLOCK finding should count
        score_single = calculate_risk_score([findings[0]])
        assert score == score_single, f"INFO/SUPPRESSED should not affect score"


class TestFinalizeFindings:
    """Test finalize_findings post-processing."""

    def test_applies_dedup_and_sorts(self):
        """finalize_findings should deduplicate and sort by confidence."""
        findings_input = [
            make_finding("AGENT-004", conf=0.70),
            make_finding("AGENT-046", "auth.ts", conf=0.85,
                        snippet="security find-generic-password"),
            make_finding("AGENT-046", "utils.ts", conf=0.80,
                        snippet="security find-generic-password"),
            make_finding("AGENT-047", conf=0.90),
        ]
        result = finalize_findings(findings_input)

        # Should have 3 findings (2 AGENT-046 deduped to 1)
        assert len(result) == 3

        # Should be sorted by confidence descending
        assert result[0].confidence >= result[1].confidence
        assert result[1].confidence >= result[2].confidence
