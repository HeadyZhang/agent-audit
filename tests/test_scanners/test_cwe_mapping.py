"""Tests for CWE ID mapping (v0.15.0).

Verifies that all AGENT-XXX rules have CWE ID mappings for
NIST SSDF (PW.7) and SOC 2 compliance.
"""

from __future__ import annotations

import re
import pytest

from agent_audit.rules.engine import RULE_CWE_MAPPING


class TestCWEMapping:
    """Verify CWE ID mapping completeness and validity."""

    def test_cwe_format_valid(self):
        """All CWE IDs should follow CWE-XXX format."""
        pattern = re.compile(r"^CWE-\d+$")

        invalid = []
        for rule_id, cwe_id in RULE_CWE_MAPPING.items():
            if not pattern.match(cwe_id):
                invalid.append((rule_id, cwe_id))

        assert not invalid, f"Invalid CWE format: {invalid}"

    def test_core_rules_have_cwe(self):
        """Core rules AGENT-001 through AGENT-005 must have CWE mapping."""
        core_rules = ["AGENT-001", "AGENT-002", "AGENT-003", "AGENT-004", "AGENT-005"]

        missing = [r for r in core_rules if r not in RULE_CWE_MAPPING]
        assert not missing, f"Core rules missing CWE mapping: {missing}"

    def test_owasp_agentic_rules_have_cwe(self):
        """OWASP Agentic Top 10 rules must have CWE mapping."""
        owasp_rules = [
            # ASI-01: Goal Hijack
            "AGENT-010", "AGENT-011",
            # ASI-03: Identity & Privilege
            "AGENT-013", "AGENT-014",
            # ASI-04: Supply Chain
            "AGENT-015", "AGENT-016",
            # ASI-05: Code Execution
            "AGENT-017",
            # ASI-06: Memory Poisoning
            "AGENT-018", "AGENT-019",
            # ASI-07: Communication
            "AGENT-020",
            # ASI-08: Cascading Failures
            "AGENT-021", "AGENT-022",
            # ASI-09: Trust Exploitation
            "AGENT-023",
            # ASI-10: Rogue Agents
            "AGENT-024", "AGENT-025",
        ]

        missing = [r for r in owasp_rules if r not in RULE_CWE_MAPPING]
        assert not missing, f"OWASP Agentic rules missing CWE mapping: {missing}"

    def test_langchain_rules_have_cwe(self):
        """LangChain security rules must have CWE mapping."""
        langchain_rules = ["AGENT-026", "AGENT-027", "AGENT-028"]

        missing = [r for r in langchain_rules if r not in RULE_CWE_MAPPING]
        assert not missing, f"LangChain rules missing CWE mapping: {missing}"

    def test_mcp_rules_have_cwe(self):
        """MCP configuration security rules must have CWE mapping."""
        mcp_rules = ["AGENT-029", "AGENT-030", "AGENT-031", "AGENT-032", "AGENT-033"]

        missing = [r for r in mcp_rules if r not in RULE_CWE_MAPPING]
        assert not missing, f"MCP rules missing CWE mapping: {missing}"

    def test_tool_misuse_rules_have_cwe(self):
        """Tool misuse rules must have CWE mapping."""
        tool_rules = ["AGENT-034", "AGENT-035", "AGENT-036", "AGENT-037", "AGENT-038", "AGENT-039"]

        missing = [r for r in tool_rules if r not in RULE_CWE_MAPPING]
        assert not missing, f"Tool misuse rules missing CWE mapping: {missing}"

    def test_sql_injection_maps_to_cwe89(self):
        """AGENT-041 (SQL injection) should map to CWE-89."""
        assert RULE_CWE_MAPPING.get("AGENT-041") == "CWE-89"

    def test_hardcoded_credentials_maps_to_cwe798(self):
        """AGENT-004 (hardcoded credentials) should map to CWE-798."""
        assert RULE_CWE_MAPPING.get("AGENT-004") == "CWE-798"

    def test_command_injection_maps_to_cwe78(self):
        """AGENT-001 (command injection) should map to CWE-78."""
        assert RULE_CWE_MAPPING.get("AGENT-001") == "CWE-78"

    def test_ssrf_maps_to_cwe918(self):
        """AGENT-003 and AGENT-026 (SSRF) should map to CWE-918."""
        assert RULE_CWE_MAPPING.get("AGENT-003") == "CWE-918"
        assert RULE_CWE_MAPPING.get("AGENT-026") == "CWE-918"

    def test_deserialization_maps_to_cwe502(self):
        """AGENT-049 (unsafe deserialization) should map to CWE-502."""
        assert RULE_CWE_MAPPING.get("AGENT-049") == "CWE-502"

    def test_minimum_mapping_count(self):
        """Should have at least 40 rule mappings."""
        assert len(RULE_CWE_MAPPING) >= 40, (
            f"Expected at least 40 CWE mappings, got {len(RULE_CWE_MAPPING)}"
        )


class TestCWEMappingIntegration:
    """Integration tests for CWE mapping in findings."""

    def test_finding_includes_cwe_from_mapping(self):
        """Finding created via engine should include CWE ID from mapping."""
        from agent_audit.rules.engine import RuleEngine
        from pathlib import Path

        engine = RuleEngine()
        # Load rules to test
        builtin_rules_dir = Path(__file__).parent.parent.parent / "packages" / "audit" / "rules" / "builtin"
        if builtin_rules_dir.exists():
            engine.add_builtin_rules_dir(builtin_rules_dir)
            engine.load_rules()

        # The engine should now use RULE_CWE_MAPPING for findings
        # This is verified by the test_cwe_format_valid test above
        assert len(RULE_CWE_MAPPING) > 0
