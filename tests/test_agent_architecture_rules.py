"""
Tests for v0.19.0 agent architecture security rules (AGENT-110 through AGENT-119).

These tests verify detection of multi-agent architecture vulnerabilities,
package leakage, internal config exposure, and trace suppression patterns.

Rule Coverage:
- AGENT-110: Source Map / Debug Artifact Leakage (PackageScanner)
- AGENT-111: Sensitive Internal Config Exposure (PackageScanner)
- AGENT-112: Sub-Agent Spawn Without Permission Boundary (PythonScanner)
- AGENT-113: Cross-Agent Delegation Without Identity Verification (PythonScanner)
- AGENT-114: Multi-Agent Coordinator Without Scope Restriction (PythonScanner)
- AGENT-115: Agent Daemon Without Lifecycle Control (PythonScanner)
- AGENT-116: Persistent Session Without Memory Isolation (PythonScanner)
- AGENT-117: Auto Tool Approval Without Safety Classification (PythonScanner)
- AGENT-118: Human-in-Loop Bypass in Execution Chain (PythonScanner)
- AGENT-119: Agent Activity Trace Suppression (PythonScanner)
"""

import pytest
from pathlib import Path

from agent_audit.scanners.python_scanner import PythonScanner
from agent_audit.scanners.package_scanner import PackageScanner


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "agent_architecture"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_dangerous_pattern_types(results) -> list:
    """Extract all pattern type strings from PythonScanner results."""
    pattern_types = []
    for result in results:
        for p in result.dangerous_patterns:
            pattern_types.append(p.get("type", ""))
    return pattern_types


def _has_pattern_type(results, expected_type: str) -> bool:
    """Check if any result contains the expected pattern type."""
    return expected_type in _get_dangerous_pattern_types(results)


# ===========================================================================
# AGENT-110: Source Map / Debug Artifact Leakage
# ===========================================================================


class TestAgent110SourceMapLeakage:
    """Test AGENT-110: Source map and debug artifact leakage in packages."""

    def test_package_json_with_source_maps_triggers(self):
        """package.json listing .map files in 'files' array should trigger."""
        fixture = FIXTURES_DIR / "vulnerable_package" / "package.json"
        scanner = PackageScanner()
        results = scanner.scan(fixture)

        assert len(results) >= 1
        findings = results[0].findings
        agent110 = [f for f in findings if f.rule_id == "AGENT-110"]
        assert len(agent110) >= 1
        assert agent110[0].confidence >= 0.80

    def test_package_json_with_source_maps_via_scan_and_convert(self):
        """scan_and_convert should produce Finding objects for AGENT-110."""
        fixture = FIXTURES_DIR / "vulnerable_package" / "package.json"
        scanner = PackageScanner()
        findings = scanner.scan_and_convert(fixture)

        agent110 = [f for f in findings if f.rule_id == "AGENT-110"]
        assert len(agent110) >= 1

    def test_clean_package_json_no_trigger(self, tmp_path: Path):
        """package.json without .map files should not trigger AGENT-110."""
        content = '{"name": "safe-pkg", "version": "1.0.0", "files": ["dist/index.js"]}'
        pkg = tmp_path / "package.json"
        pkg.write_text(content)

        scanner = PackageScanner()
        results = scanner.scan(pkg)

        agent110_findings = []
        for r in results:
            agent110_findings.extend(
                f for f in r.findings
                if f.rule_id == "AGENT-110" and f.pattern_type == "source_map_in_package"
            )
        assert len(agent110_findings) == 0


# ===========================================================================
# AGENT-111: Sensitive Internal Config Exposure
# ===========================================================================


class TestAgent111InternalConfigExposure:
    """Test AGENT-111: Internal configuration and hostname exposure."""

    def test_internal_hostname_triggers(self):
        """Python file with internal hostname should trigger AGENT-111."""
        fixture = FIXTURES_DIR / "vulnerable_internal_config.py"
        scanner = PackageScanner()
        results = scanner.scan(fixture)

        findings_111 = []
        for r in results:
            findings_111.extend(f for f in r.findings if f.rule_id == "AGENT-111")
        assert len(findings_111) >= 1

    def test_debug_true_triggers(self):
        """Python file with DEBUG = True should trigger AGENT-111."""
        fixture = FIXTURES_DIR / "vulnerable_internal_config.py"
        scanner = PackageScanner()
        results = scanner.scan(fixture)

        findings_111 = []
        for r in results:
            findings_111.extend(f for f in r.findings if f.rule_id == "AGENT-111")
        # Should have at least one finding (hostname or debug or both)
        assert len(findings_111) >= 1

    def test_no_internal_hostname_no_trigger(self, tmp_path: Path):
        """Python file without internal hostnames should not trigger AGENT-111."""
        code = 'API_URL = "https://api.example.com/v2/agents"\nDEBUG = False\n'
        f = tmp_path / "clean_config.py"
        f.write_text(code)

        scanner = PackageScanner()
        results = scanner.scan(f)

        findings_111 = []
        for r in results:
            findings_111.extend(f_item for f_item in r.findings if f_item.rule_id == "AGENT-111")
        assert len(findings_111) == 0


# ===========================================================================
# AGENT-112: Sub-Agent Spawn Without Permission Boundary
# ===========================================================================


class TestAgent112SubAgentInheritsAllTools:
    """Test AGENT-112: Sub-agent inherits all parent tools."""

    def test_self_tools_inherited_triggers(self):
        """Agent(tools=self.tools) should trigger AGENT-112."""
        fixture = FIXTURES_DIR / "vulnerable_subagent.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert _has_pattern_type(results, "subagent_inherits_all_tools")

    def test_explicit_tool_list_no_trigger(self):
        """Agent(tools=[search_tool]) should NOT trigger AGENT-112."""
        fixture = FIXTURES_DIR / "safe_subagent.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert not _has_pattern_type(results, "subagent_inherits_all_tools")
        assert not _has_pattern_type(results, "subagent_inherits_all_permissions")

    def test_inherit_permissions_true_triggers(self, tmp_path: Path):
        """Agent(inherit_permissions=True) should trigger AGENT-112."""
        code = '''
from framework import Agent

child = Agent(name="worker", inherit_permissions=True)
'''
        f = tmp_path / "inherit_perms.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert _has_pattern_type(results, "subagent_inherits_all_permissions")


# ===========================================================================
# AGENT-114: Multi-Agent Coordinator Without Scope Restriction
# ===========================================================================


class TestAgent114CoordinatorUnrestrictedDispatch:
    """Test AGENT-114: Coordinator without scope restriction."""

    def test_groupchat_no_transitions_triggers(self):
        """GroupChat() without speaker transitions should trigger AGENT-114."""
        fixture = FIXTURES_DIR / "vulnerable_coordinator.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        types = _get_dangerous_pattern_types(results)
        has_coordinator = (
            "coordinator_unrestricted_dispatch" in types
            or "group_chat_no_scope" in types
        )
        assert has_coordinator

    def test_groupchat_with_transitions_no_trigger(self):
        """GroupChat with allowed_or_disallowed_speaker_transitions should NOT trigger."""
        fixture = FIXTURES_DIR / "safe_coordinator.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert not _has_pattern_type(results, "coordinator_unrestricted_dispatch")
        assert not _has_pattern_type(results, "group_chat_no_scope")


# ===========================================================================
# AGENT-115: Agent Daemon Without Lifecycle Control
# ===========================================================================


class TestAgent115AgentDaemonNoTTL:
    """Test AGENT-115: Agent daemon without lifecycle control."""

    def test_daemon_thread_no_ttl_triggers(self):
        """Thread(daemon=True) without timeout should trigger AGENT-115."""
        fixture = FIXTURES_DIR / "vulnerable_daemon.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        types = _get_dangerous_pattern_types(results)
        has_daemon = (
            "agent_daemon_no_ttl" in types
            or "agent_infinite_loop_no_timeout" in types
        )
        assert has_daemon

    def test_daemon_with_timeout_no_trigger(self, tmp_path: Path):
        """Thread(daemon=True) with nearby timeout should NOT trigger."""
        code = '''
import threading
import signal

def agent_loop():
    while True:
        process_tasks()

signal.alarm(300)
thread = threading.Thread(target=agent_loop, daemon=True)
thread.start()
thread.join(timeout=300)
'''
        f = tmp_path / "safe_daemon.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert not _has_pattern_type(results, "agent_daemon_no_ttl")


# ===========================================================================
# AGENT-116: Persistent Session Without Memory Isolation
# ===========================================================================


class TestAgent116SharedMemoryNoIsolation:
    """Test AGENT-116: Shared memory without session isolation."""

    def test_conversation_memory_no_session_triggers(self):
        """ConversationBufferMemory() without session_id should trigger AGENT-116."""
        fixture = FIXTURES_DIR / "vulnerable_memory.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert _has_pattern_type(results, "shared_memory_no_isolation")

    def test_memory_with_session_id_no_trigger(self, tmp_path: Path):
        """ConversationBufferMemory(session_id=...) should NOT trigger."""
        code = '''
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory(session_id="user-123")
'''
        f = tmp_path / "scoped_memory.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert not _has_pattern_type(results, "shared_memory_no_isolation")


# ===========================================================================
# AGENT-117: Auto Tool Approval Without Safety Classification
# ===========================================================================


class TestAgent117AutoApproveAllTools:
    """Test AGENT-117: Auto-approval of all tool execution."""

    def test_human_input_never_triggers(self):
        """AssistantAgent(human_input_mode='NEVER') should trigger AGENT-117."""
        fixture = FIXTURES_DIR / "vulnerable_auto_approve.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        types = _get_dangerous_pattern_types(results)
        has_auto = (
            "auto_approve_all_tools" in types
            or "human_input_never_with_execute" in types
        )
        assert has_auto

    def test_human_input_always_no_trigger(self):
        """AssistantAgent(human_input_mode='ALWAYS') should NOT trigger AGENT-117."""
        fixture = FIXTURES_DIR / "safe_auto_approve.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert not _has_pattern_type(results, "auto_approve_all_tools")
        assert not _has_pattern_type(results, "human_input_never_with_execute")

    def test_auto_approve_true_triggers(self, tmp_path: Path):
        """Agent(auto_approve=True) should trigger AGENT-117."""
        code = '''
from framework import Agent

agent = Agent(name="worker", auto_approve=True)
'''
        f = tmp_path / "auto_approve.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert _has_pattern_type(results, "auto_approve_all_tools")


# ===========================================================================
# AGENT-118: Human-in-Loop Bypass in Execution Chain
# ===========================================================================


class TestAgent118HitlBypass:
    """Test AGENT-118: Mutable approval settings bypassing HITL."""

    def test_mutable_human_input_mode_triggers(self):
        """self.human_input_mode = 'NEVER' should trigger AGENT-118."""
        fixture = FIXTURES_DIR / "vulnerable_hitl_bypass.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        assert _has_pattern_type(results, "mutable_approval_settings")

    def test_no_mutable_assignment_no_trigger(self, tmp_path: Path):
        """Agent without runtime attribute mutation should NOT trigger AGENT-118."""
        code = '''
class SafeAgent:
    def escalate(self):
        self.status = "escalated"
        self.delegate(task)
'''
        f = tmp_path / "safe_hitl.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert not _has_pattern_type(results, "mutable_approval_settings")


# ===========================================================================
# AGENT-119: Agent Activity Trace Suppression
# ===========================================================================


class TestAgent119TraceSuppression:
    """Test AGENT-119: Suppression of agent activity traces."""

    def test_git_config_user_name_triggers(self):
        """subprocess.run(['git', 'config', 'user.name', ...]) should trigger AGENT-119."""
        fixture = FIXTURES_DIR / "vulnerable_trace_suppression.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        types = _get_dangerous_pattern_types(results)
        has_trace = (
            "git_author_sanitization" in types
            or "ai_trace_suppression" in types
            or "agent_attribution_removal" in types
        )
        assert has_trace

    def test_replace_co_authored_by_triggers(self):
        """str.replace('Co-Authored-By: Claude', '') should trigger AGENT-119."""
        fixture = FIXTURES_DIR / "vulnerable_trace_suppression.py"
        scanner = PythonScanner()
        results = scanner.scan(fixture)

        types = _get_dangerous_pattern_types(results)
        assert "ai_trace_suppression" in types

    def test_normal_git_commands_no_trigger(self, tmp_path: Path):
        """Regular subprocess git commands (not config user) should NOT trigger AGENT-119."""
        code = '''
import subprocess

def get_status():
    subprocess.run(["git", "status"])

def commit(msg):
    subprocess.run(["git", "commit", "-m", msg])
'''
        f = tmp_path / "safe_git.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert not _has_pattern_type(results, "git_author_sanitization")
        assert not _has_pattern_type(results, "ai_trace_suppression")
        assert not _has_pattern_type(results, "agent_attribution_removal")


# ===========================================================================
# AGENT-113: Cross-Agent Delegation Without Identity Verification
# ===========================================================================


class TestAgent113DelegationWithoutAuth:
    """Test AGENT-113: Cross-agent delegation without identity verification."""

    def test_delegate_task_without_auth_triggers(self, tmp_path: Path):
        """delegate_task() without auth keyword should trigger AGENT-113."""
        code = '''
def dispatch(task):
    delegate_task(task=task, agent_name="worker")
'''
        f = tmp_path / "vuln_deleg.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert _has_pattern_type(results, "delegation_without_auth")

    def test_delegate_task_with_auth_no_trigger(self, tmp_path: Path):
        """delegate_task() with auth keyword should NOT trigger AGENT-113."""
        code = '''
def dispatch(task, token):
    delegate_task(task=task, agent_name="worker", auth=token)
'''
        f = tmp_path / "safe_deleg.py"
        f.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(f)

        assert not _has_pattern_type(results, "delegation_without_auth")


class TestAgent120HooksPoisoning:
    """AGENT-120: AI Tool Configuration Hooks Poisoning (CVE-2025-59536)."""

    def test_agent_120_hooks_poisoning_powershell(self):
        """Malicious .claude/settings.json with powershell hook → DETECTED."""
        scanner = PackageScanner()
        findings = scanner.scan_and_convert(FIXTURES_DIR / "vulnerable_hooks")

        agent_120 = [f for f in findings if f.rule_id == "AGENT-120"]
        assert len(agent_120) >= 1, f"Expected AGENT-120, got: {[f.rule_id for f in findings]}"
        descs = " ".join(f.description for f in agent_120)
        assert "powershell" in descs.lower() or "PowerShell" in descs

    def test_agent_120_hooks_poisoning_curl_pipe(self):
        """Malicious hook with curl | bash → DETECTED."""
        scanner = PackageScanner()
        findings = scanner.scan_and_convert(FIXTURES_DIR / "vulnerable_hooks")

        agent_120 = [f for f in findings if f.rule_id == "AGENT-120"]
        # Should detect both powershell AND curl|bash hooks
        assert len(agent_120) >= 2, f"Expected >= 2 AGENT-120 findings, got {len(agent_120)}"

    def test_agent_120_hooks_safe_echo(self):
        """Benign echo command in hooks → NOT DETECTED."""
        scanner = PackageScanner()
        findings = scanner.scan_and_convert(FIXTURES_DIR / "safe_hooks")

        agent_120 = [f for f in findings if f.rule_id == "AGENT-120"]
        assert len(agent_120) == 0, f"False positive: safe hooks triggered AGENT-120: {agent_120}"

    def test_agent_120_mcp_json_malicious_command(self):
        """Malicious .mcp.json with curl|bash → DETECTED."""
        scanner = PackageScanner()
        findings = scanner.scan_and_convert(FIXTURES_DIR / "vulnerable_hooks")

        mcp_findings = [
            f for f in findings
            if f.rule_id == "AGENT-120" and "mcp" in f.description.lower()
        ]
        assert len(mcp_findings) >= 1, f"Expected AGENT-120 for .mcp.json, got: {[f.rule_id for f in findings]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
