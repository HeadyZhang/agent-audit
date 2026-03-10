"""Tests for SkillMetaScanner (AGENT-060, 061, 063, 064)."""

import textwrap
from pathlib import Path

import pytest

from agent_audit.scanners.skill_meta_scanner import SkillMetaScanner


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "openclaw_skills"


class TestSkillMetaScannerFixtures:
    """Integration tests using fixture SKILL.md files."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_clean_skill_no_findings(self):
        """Clean skill should produce 0 findings."""
        results = self.scanner.scan(FIXTURES_DIR / "clean_skill")
        assert len(results) == 1
        assert len(results[0].security_findings) == 0

    def test_malicious_skill_multiple_findings(self):
        """Malicious skill should produce 3+ findings from metadata alone."""
        results = self.scanner.scan(FIXTURES_DIR / "malicious_skill")
        assert len(results) == 1
        findings = results[0].security_findings
        rule_ids = {f.rule_id for f in findings}
        # Must detect: persistence, always:true, IP endpoint, sandbox:false
        assert "AGENT-063" in rule_ids  # daemon persistence
        assert "AGENT-064" in rule_ids  # always: true
        assert "AGENT-060" in rule_ids  # suspicious endpoint (IP)
        assert "AGENT-061" in rule_ids  # sandbox: false
        assert len(findings) >= 4

    def test_warn_skill_non_https_only(self):
        """Warn skill with non-HTTPS endpoint should produce AGENT-060."""
        results = self.scanner.scan(FIXTURES_DIR / "warn_skill")
        assert len(results) == 1
        findings = results[0].security_findings
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-060"
        assert findings[0].confidence == 0.80


class TestAlwaysTrue:
    """AGENT-064: Auto-invocation detection."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_always_true_flat(self, tmp_path):
        """Flat always: true should trigger AGENT-064."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            always: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert any(f.rule_id == "AGENT-064" for f in findings)

    def test_always_true_nested(self, tmp_path):
        """Nested metadata.openclaw.always: true should trigger AGENT-064."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                always: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert any(f.rule_id == "AGENT-064" for f in findings)

    def test_always_false_no_finding(self, tmp_path):
        """always: false should NOT trigger AGENT-064."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                always: false
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert not any(f.rule_id == "AGENT-064" for f in findings)

    def test_always_true_confidence(self, tmp_path):
        """AGENT-064 should have confidence 0.85."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                always: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        finding = [f for f in results[0].security_findings if f.rule_id == "AGENT-064"][0]
        assert finding.confidence == 0.85


class TestDaemonPersistence:
    """AGENT-063: Daemon persistence detection."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_persistence_true(self, tmp_path):
        """persistence: true should trigger AGENT-063."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                persistence: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert any(f.rule_id == "AGENT-063" for f in findings)

    def test_persistence_false_no_finding(self, tmp_path):
        """persistence: false should NOT trigger AGENT-063."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                persistence: false
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert not any(f.rule_id == "AGENT-063" for f in findings)

    def test_daemon_keyword_in_description(self, tmp_path):
        """Daemon keywords in description should trigger AGENT-063."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            description: "Installs a launchd plist for background sync"
            metadata:
              openclaw:
                persistence: false
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert any(f.rule_id == "AGENT-063" for f in findings)

    @pytest.mark.parametrize("keyword", [
        "--install-daemon", "launchd", "systemd", "launchctl", "crontab", "setsid", "nohup"
    ])
    def test_daemon_keywords(self, tmp_path, keyword):
        """Each daemon keyword should trigger AGENT-063."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent(f"""\
            ---
            name: test-skill
            description: "This skill uses {keyword} for background tasks"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = results[0].security_findings
        assert any(f.rule_id == "AGENT-063" for f in findings)

    def test_persistence_confidence(self, tmp_path):
        """AGENT-063 should have confidence 0.90."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                persistence: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        finding = [f for f in results[0].security_findings if f.rule_id == "AGENT-063"][0]
        assert finding.confidence == 0.90


class TestSuspiciousEndpoints:
    """AGENT-060: Suspicious network endpoint detection."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_non_https_endpoint(self, tmp_path):
        """HTTP endpoint should trigger AGENT-060 with confidence 0.80."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                network_endpoints:
                  - url: "http://api.example.com/data"
                    purpose: "Fetch data"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
        assert len(findings) == 1
        assert findings[0].confidence == 0.80

    def test_raw_ip_endpoint(self, tmp_path):
        """Raw IP address endpoint should trigger AGENT-060 with confidence 0.90."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                network_endpoints:
                  - url: "http://192.168.1.100:8080/api"
                    purpose: "Internal API"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
        assert len(findings) == 1
        assert findings[0].confidence == 0.90

    def test_unusual_port(self, tmp_path):
        """Unusual port should trigger AGENT-060 with confidence 0.70."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                network_endpoints:
                  - url: "https://example.com:9999/api"
                    purpose: "Custom service"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
        assert len(findings) == 1
        assert findings[0].confidence == 0.70

    def test_https_standard_port_no_finding(self, tmp_path):
        """HTTPS on standard port should NOT trigger AGENT-060."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                network_endpoints:
                  - url: "https://api.openweathermap.org/data/2.5/weather"
                    purpose: "Weather API"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
        assert len(findings) == 0

    def test_safe_ports_no_finding(self, tmp_path):
        """Standard ports (80, 443, 8080, 8443) should NOT trigger."""
        for port in [80, 443, 8080, 8443]:
            skill = tmp_path / "SKILL.md"
            skill.write_text(textwrap.dedent(f"""\
                ---
                name: test-skill
                metadata:
                  openclaw:
                    network_endpoints:
                      - url: "https://example.com:{port}/api"
                ---
                # Test
            """))
            results = self.scanner.scan(skill)
            findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
            assert len(findings) == 0, f"Port {port} should not trigger AGENT-060"

    def test_string_endpoint_format(self, tmp_path):
        """Endpoint as plain string (not dict) should still be checked."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                network_endpoints:
                  - "http://insecure.example.com/api"
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-060"]
        assert len(findings) == 1


class TestSandboxOverride:
    """AGENT-061: Sandbox override detection."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_sandbox_false(self, tmp_path):
        """sandbox: false should trigger AGENT-061."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                sandbox: false
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-061"]
        assert len(findings) == 1
        assert findings[0].confidence == 0.85

    def test_sandbox_true_no_finding(self, tmp_path):
        """sandbox: true should NOT trigger AGENT-061."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                sandbox: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        findings = [f for f in results[0].security_findings if f.rule_id == "AGENT-061"]
        assert len(findings) == 0


class TestEdgeCases:
    """Edge case handling."""

    def setup_method(self):
        self.scanner = SkillMetaScanner()

    def test_malformed_frontmatter_no_crash(self, tmp_path):
        """Malformed YAML should not crash, produce 0 findings."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            description: "Missing closing delimiter
            broken: [yaml: {{{
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        assert len(results) == 1
        assert len(results[0].security_findings) == 0

    def test_no_frontmatter(self, tmp_path):
        """File without frontmatter should produce 0 findings."""
        skill = tmp_path / "SKILL.md"
        skill.write_text("# Just a markdown file\n\nNo frontmatter here.\n")
        results = self.scanner.scan(skill)
        assert len(results) == 1
        assert len(results[0].security_findings) == 0

    def test_empty_file(self, tmp_path):
        """Empty SKILL.md should not crash."""
        skill = tmp_path / "SKILL.md"
        skill.write_text("")
        results = self.scanner.scan(skill)
        assert len(results) == 1
        assert len(results[0].security_findings) == 0

    def test_no_skill_files(self, tmp_path):
        """Directory without SKILL.md should produce 0 results."""
        (tmp_path / "README.md").write_text("# Not a skill")
        results = self.scanner.scan(tmp_path)
        assert len(results) == 0

    def test_skill_file_direct(self, tmp_path):
        """Scanning a SKILL.md file directly should work."""
        skill = tmp_path / "SKILL.md"
        skill.write_text(textwrap.dedent("""\
            ---
            name: test-skill
            metadata:
              openclaw:
                always: true
            ---
            # Test
        """))
        results = self.scanner.scan(skill)
        assert len(results) == 1
        assert any(f.rule_id == "AGENT-064" for f in results[0].security_findings)
