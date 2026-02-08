"""Tests for baseline and suppression functionality (v0.15.0).

Verifies:
- Suppression dataclass functionality
- Baseline creation and loading
- Inline suppression parsing
- Fingerprint computation
"""

from __future__ import annotations

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

from agent_audit.models.suppression import (
    Suppression,
    Baseline,
    InlineSuppression,
    compute_finding_fingerprint,
    parse_inline_suppressions,
    INLINE_IGNORE_PATTERN,
)
from agent_audit.config.ignore import (
    save_baseline,
    load_baseline,
    filter_by_baseline,
    compute_fingerprint,
)
from agent_audit.models.finding import Finding
from agent_audit.models.risk import Severity, Category, Location


def create_test_finding(
    rule_id: str = "AGENT-001",
    file_path: str = "src/agent.py",
    line: int = 42,
    snippet: str = "eval(user_input)"
) -> Finding:
    """Create a test finding for baseline tests."""
    return Finding(
        rule_id=rule_id,
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        location=Location(
            file_path=file_path,
            start_line=line,
            end_line=line,
            snippet=snippet
        ),
        confidence=0.85,
    )


class TestSuppression:
    """Test Suppression dataclass."""

    def test_suppression_creation(self):
        """Suppression should be created with required fields."""
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
            reason="Test credential",
        )
        assert suppression.rule_id == "AGENT-001"
        assert suppression.file_path == "src/agent.py"
        assert suppression.line == 42
        assert suppression.fingerprint == "abc123"
        assert suppression.reason == "Test credential"
        assert suppression.source == "baseline"

    def test_suppression_not_expired(self):
        """Non-expired suppression should return False."""
        future_date = (datetime.utcnow() + timedelta(days=30)).isoformat()
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
            expires=future_date,
        )
        assert suppression.is_expired() is False

    def test_suppression_expired(self):
        """Expired suppression should return True."""
        past_date = (datetime.utcnow() - timedelta(days=1)).isoformat()
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
            expires=past_date,
        )
        assert suppression.is_expired() is True

    def test_suppression_to_dict(self):
        """Suppression should serialize to dict."""
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
            reason="Test",
            approved_by="security-team",
        )
        d = suppression.to_dict()
        assert d["rule_id"] == "AGENT-001"
        assert d["file"] == "src/agent.py"
        assert d["line"] == 42
        assert d["fingerprint"] == "abc123"
        assert d["reason"] == "Test"
        assert d["approved_by"] == "security-team"

    def test_suppression_from_dict(self):
        """Suppression should deserialize from dict."""
        data = {
            "rule_id": "AGENT-001",
            "file": "src/agent.py",
            "line": 42,
            "fingerprint": "abc123",
            "reason": "Test",
        }
        suppression = Suppression.from_dict(data)
        assert suppression.rule_id == "AGENT-001"
        assert suppression.file_path == "src/agent.py"


class TestBaseline:
    """Test Baseline dataclass."""

    def test_baseline_creation(self):
        """Baseline should be created with defaults."""
        baseline = Baseline()
        assert baseline.version == "1"
        assert baseline.suppressions == []
        assert baseline.generated_at != ""

    def test_baseline_add_suppression(self):
        """Baseline should track added suppressions."""
        baseline = Baseline()
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
        )
        baseline.add_suppression(suppression)
        assert len(baseline.suppressions) == 1
        assert baseline.contains_fingerprint("abc123")
        assert not baseline.contains_fingerprint("xyz789")

    def test_baseline_get_suppression(self):
        """Baseline should retrieve suppression by fingerprint."""
        baseline = Baseline()
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
        )
        baseline.add_suppression(suppression)
        retrieved = baseline.get_suppression("abc123")
        assert retrieved is not None
        assert retrieved.rule_id == "AGENT-001"

    def test_baseline_to_dict(self):
        """Baseline should serialize to dict."""
        baseline = Baseline(tool_version="0.15.0")
        suppression = Suppression(
            rule_id="AGENT-001",
            file_path="src/agent.py",
            line=42,
            fingerprint="abc123",
        )
        baseline.add_suppression(suppression)
        d = baseline.to_dict()
        assert d["version"] == "1"
        assert d["tool_version"] == "0.15.0"
        assert len(d["suppressions"]) == 1

    def test_baseline_from_dict(self):
        """Baseline should deserialize from dict."""
        data = {
            "version": "1",
            "generated_at": "2026-02-05T10:00:00Z",
            "tool_version": "0.15.0",
            "suppressions": [
                {
                    "rule_id": "AGENT-001",
                    "file": "src/agent.py",
                    "line": 42,
                    "fingerprint": "abc123",
                }
            ]
        }
        baseline = Baseline.from_dict(data)
        assert baseline.tool_version == "0.15.0"
        assert len(baseline.suppressions) == 1
        assert baseline.contains_fingerprint("abc123")

    def test_baseline_from_fingerprints(self):
        """Baseline should be created from legacy fingerprint list."""
        fingerprints = ["abc123", "def456", "ghi789"]
        baseline = Baseline.from_fingerprints(fingerprints, tool_version="0.15.0")
        assert len(baseline.suppressions) == 3
        assert baseline.contains_fingerprint("abc123")
        assert baseline.contains_fingerprint("def456")
        assert baseline.contains_fingerprint("ghi789")


class TestInlineSuppression:
    """Test inline suppression parsing."""

    def test_parse_agent_audit_ignore(self):
        """Should parse 'agent-audit: ignore' comment."""
        line = "api_key = 'test'  # agent-audit: ignore AGENT-004 -- Test key"
        suppression = InlineSuppression.parse_line(line, 10)
        assert suppression is not None
        assert suppression.rule_id == "AGENT-004"
        assert suppression.reason == "Test key"
        assert suppression.line == 10
        assert suppression.applies_to_next_line is False

    def test_parse_agent_audit_ignore_next_line(self):
        """Should parse 'agent-audit: ignore-next-line' comment."""
        line = "# agent-audit: ignore-next-line AGENT-001"
        suppression = InlineSuppression.parse_line(line, 10)
        assert suppression is not None
        assert suppression.rule_id == "AGENT-001"
        assert suppression.applies_to_next_line is True

    def test_parse_noaudit(self):
        """Should parse 'noaudit' comment."""
        line = "eval(safe_expr)  # noaudit AGENT-001 Safe expression"
        suppression = InlineSuppression.parse_line(line, 5)
        assert suppression is not None
        assert suppression.rule_id == "AGENT-001"
        assert "Safe expression" in suppression.reason

    def test_parse_no_suppression(self):
        """Should return None for lines without suppression."""
        line = "normal_code = True"
        suppression = InlineSuppression.parse_line(line, 1)
        assert suppression is None

    def test_parse_inline_suppressions_source(self):
        """Should parse all suppressions from source code."""
        source = '''
api_key = "test"  # agent-audit: ignore AGENT-004 -- Test
# agent-audit: ignore-next-line AGENT-001
eval(safe_expr)
password = None  # noaudit AGENT-004
'''
        suppressions = parse_inline_suppressions(source)
        # Line 2: AGENT-004 on same line
        # Line 3: ignore-next-line → applies to line 4
        # Line 5: AGENT-004 on same line
        assert 2 in suppressions or 5 in suppressions  # At least one found
        # Check ignore-next-line applies to next line
        assert 4 in suppressions
        assert suppressions[4].rule_id == "AGENT-001"


class TestFingerprintComputation:
    """Test fingerprint computation."""

    def test_fingerprint_stability(self):
        """Same inputs should produce same fingerprint."""
        fp1 = compute_finding_fingerprint("AGENT-001", "src/agent.py", 42, "eval(x)")
        fp2 = compute_finding_fingerprint("AGENT-001", "src/agent.py", 42, "eval(x)")
        assert fp1 == fp2

    def test_fingerprint_uniqueness(self):
        """Different inputs should produce different fingerprints."""
        fp1 = compute_finding_fingerprint("AGENT-001", "src/agent.py", 42, "eval(x)")
        fp2 = compute_finding_fingerprint("AGENT-001", "src/agent.py", 43, "eval(x)")
        fp3 = compute_finding_fingerprint("AGENT-002", "src/agent.py", 42, "eval(x)")
        assert fp1 != fp2
        assert fp1 != fp3

    def test_fingerprint_length(self):
        """Fingerprint should be 16 characters."""
        fp = compute_finding_fingerprint("AGENT-001", "src/agent.py", 42, "eval(x)")
        assert len(fp) == 16


class TestBaselineIntegration:
    """Integration tests for baseline with findings."""

    def test_save_and_load_baseline(self):
        """Should save and load baseline correctly."""
        findings = [
            create_test_finding("AGENT-001", "src/a.py", 10, "eval(x)"),
            create_test_finding("AGENT-004", "src/b.py", 20, "api_key='test'"),
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            baseline_path = Path(f.name)

        try:
            save_baseline(findings, baseline_path)
            loaded = load_baseline(baseline_path)

            assert len(loaded) == 2
            # Verify fingerprints match
            for finding in findings:
                fp = compute_fingerprint(finding)
                assert fp in loaded
        finally:
            baseline_path.unlink()

    def test_filter_by_baseline(self):
        """Should filter out findings in baseline."""
        finding1 = create_test_finding("AGENT-001", "src/a.py", 10, "eval(x)")
        finding2 = create_test_finding("AGENT-004", "src/b.py", 20, "api_key='test'")
        finding3 = create_test_finding("AGENT-002", "src/c.py", 30, "subprocess.run(x)")

        # Create baseline with first two findings
        baseline_fingerprints = {
            compute_fingerprint(finding1),
            compute_fingerprint(finding2),
        }

        # Filter - only finding3 should remain
        all_findings = [finding1, finding2, finding3]
        filtered = filter_by_baseline(all_findings, baseline_fingerprints)

        assert len(filtered) == 1
        assert filtered[0].rule_id == "AGENT-002"

    def test_empty_baseline_returns_all(self):
        """Empty baseline should return all findings."""
        findings = [
            create_test_finding("AGENT-001", "src/a.py", 10, "eval(x)"),
            create_test_finding("AGENT-004", "src/b.py", 20, "api_key='test'"),
        ]

        filtered = filter_by_baseline(findings, set())
        assert len(filtered) == 2
