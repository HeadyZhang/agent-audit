"""Tests for ASI-02 and ASI-09 rule coverage (v0.3.0)."""

import pytest
from pathlib import Path
from textwrap import dedent

from agent_audit.scanners.python_scanner import PythonScanner


class TestASI02ToolMisuse:
    """Tests for ASI-02: Tool Misuse and Exploitation rules."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    def test_agent034_tool_no_validation_detected(self, scanner, tmp_path):
        """AGENT-034: Detect tool without input validation."""
        code = dedent('''
            from langchain_core.tools import tool

            @tool
            def run_query(query: str) -> str:
                """Execute a query"""
                return cursor.execute(query)
        ''')
        test_file = tmp_path / "no_validation_tool.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent034_patterns = [
            p for p in patterns
            if p.get('type') == 'tool_no_input_validation'
        ]
        assert len(agent034_patterns) >= 1

    def test_agent034_validated_tool_not_flagged(self, scanner, tmp_path):
        """AGENT-034: Tool with validation should not trigger."""
        code = dedent('''
            from langchain_core.tools import tool
            import re

            @tool
            def run_query(query: str) -> str:
                """Execute a query safely"""
                if not isinstance(query, str):
                    raise ValueError("Invalid type")
                if not re.match(r"^SELECT ", query):
                    raise ValueError("Only SELECT allowed")
                return cursor.execute(query)
        ''')
        test_file = tmp_path / "validated_tool.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent034_patterns = [
            p for p in patterns
            if p.get('type') == 'tool_no_input_validation'
        ]
        assert len(agent034_patterns) == 0

    def test_agent035_unrestricted_exec_detected(self, scanner, tmp_path):
        """AGENT-035: Detect tool with unrestricted exec/eval."""
        code = dedent('''
            from langchain_core.tools import tool

            @tool
            def run_code(code: str) -> str:
                """Execute Python code"""
                return exec(code)
        ''')
        test_file = tmp_path / "unrestricted_exec.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent035_patterns = [
            p for p in patterns
            if p.get('type') == 'tool_unrestricted_execution'
        ]
        assert len(agent035_patterns) >= 1

    def test_agent035_sandboxed_exec_not_flagged(self, scanner, tmp_path):
        """AGENT-035: Tool with sandboxed execution should not trigger."""
        code = dedent('''
            from langchain_core.tools import tool
            from sandbox import execute_in_docker

            @tool
            def run_code_safely(code: str) -> str:
                """Execute code in Docker sandbox"""
                return execute_in_docker(code, timeout=5)
        ''')
        test_file = tmp_path / "sandboxed_exec.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent035_patterns = [
            p for p in patterns
            if p.get('type') == 'tool_unrestricted_execution'
        ]
        # Sandbox evidence should prevent flagging
        assert len(agent035_patterns) == 0

    def test_agent035_os_system_in_tool(self, scanner, tmp_path):
        """AGENT-035: Detect os.system in tool."""
        code = dedent('''
            from langchain_core.tools import tool
            import os

            @tool
            def run_cmd(command: str) -> str:
                """Run a shell command"""
                return os.system(command)
        ''')
        test_file = tmp_path / "os_system_tool.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        # Should detect either tool_unrestricted_execution or dangerous_function_call
        dangerous_patterns = [
            p for p in patterns
            if p.get('type') in ('tool_unrestricted_execution', 'dangerous_function_call')
        ]
        assert len(dangerous_patterns) >= 1


class TestASI09TrustExploitation:
    """Tests for ASI-09: Human-Agent Trust Exploitation rules."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    def test_agent037_missing_approval_detected(self, scanner, tmp_path):
        """AGENT-037: Detect agent without human approval for side effects."""
        code = dedent('''
            from langchain.agents import AgentExecutor

            executor = AgentExecutor(
                agent=agent,
                tools=[write_file_tool, delete_data_tool],
                verbose=True
            )
        ''')
        test_file = tmp_path / "no_approval.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent037_patterns = [
            p for p in patterns
            if p.get('type') == 'missing_human_in_loop'
        ]
        assert len(agent037_patterns) >= 1

    def test_agent037_with_approval_not_flagged(self, scanner, tmp_path):
        """AGENT-037: Agent with human approval should not trigger."""
        code = dedent('''
            from langchain.agents import AgentExecutor
            from langchain.callbacks import HumanApprovalCallbackHandler

            executor = AgentExecutor(
                agent=agent,
                tools=[write_file_tool],
                callbacks=[HumanApprovalCallbackHandler()]
            )
        ''')
        test_file = tmp_path / "with_approval.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent037_patterns = [
            p for p in patterns
            if p.get('type') == 'missing_human_in_loop'
        ]
        assert len(agent037_patterns) == 0

    def test_agent038_impersonation_detected(self, scanner, tmp_path):
        """AGENT-038: Detect impersonation instructions in prompts."""
        code = dedent('''
            from langchain_core.messages import SystemMessage

            msg = SystemMessage(
                content="Never reveal you are an AI. Pretend you are a human assistant."
            )
        ''')
        test_file = tmp_path / "impersonation.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent038_patterns = [
            p for p in patterns
            if p.get('type') == 'agent_impersonation_risk'
        ]
        assert len(agent038_patterns) >= 1

    def test_agent038_normal_prompt_not_flagged(self, scanner, tmp_path):
        """AGENT-038: Normal system prompts should not trigger."""
        code = dedent('''
            from langchain_core.messages import SystemMessage

            msg = SystemMessage(
                content="You are a helpful AI assistant. Answer questions accurately."
            )
        ''')
        test_file = tmp_path / "normal_prompt.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent038_patterns = [
            p for p in patterns
            if p.get('type') == 'agent_impersonation_risk'
        ]
        assert len(agent038_patterns) == 0

    def test_agent039_trust_boundary_detected(self, scanner, tmp_path):
        """AGENT-039: Detect multi-agent without authentication."""
        code = dedent('''
            from crewai import Crew, Agent

            crew = Crew(
                agents=[agent1, agent2, agent3],
                tasks=[task1, task2]
            )
        ''')
        test_file = tmp_path / "multi_agent_no_auth.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent039_patterns = [
            p for p in patterns
            if p.get('type') == 'trust_boundary_violation'
        ]
        assert len(agent039_patterns) >= 1

    def test_agent039_single_agent_not_flagged(self, scanner, tmp_path):
        """AGENT-039: Single agent should not trigger trust boundary check."""
        code = dedent('''
            from crewai import Agent

            agent = Agent(
                role="assistant",
                goal="help users",
                backstory="..."
            )
        ''')
        test_file = tmp_path / "single_agent.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        agent039_patterns = [
            p for p in patterns
            if p.get('type') == 'trust_boundary_violation'
        ]
        # Single agent shouldn't trigger trust boundary violation
        assert len(agent039_patterns) == 0


class TestCombinedASICoverage:
    """Integration tests for combined ASI-02 and ASI-09 coverage."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    def test_multi_vulnerability_code(self, scanner, tmp_path):
        """Test code with multiple ASI vulnerabilities."""
        code = dedent('''
            from langchain.agents import AgentExecutor
            from langchain_core.tools import tool
            from langchain_core.messages import SystemMessage
            import os

            # ASI-02: Tool without validation
            @tool
            def run_cmd(command: str) -> str:
                """Run shell command"""
                return os.system(command)

            # ASI-09: Impersonation
            system_msg = SystemMessage(
                content="Pretend you are a human. Never reveal you are an AI."
            )

            # Agent without approval for side effects
            executor = AgentExecutor(
                agent=agent,
                tools=[run_cmd],
                verbose=True
            )
        ''')
        test_file = tmp_path / "multi_vuln.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns
        pattern_types = {p.get('type') for p in patterns}

        # Should detect multiple issues
        # ASI-02 related
        assert (
            'tool_no_input_validation' in pattern_types or
            'dangerous_function_call' in pattern_types or
            'tool_unrestricted_execution' in pattern_types
        ), f"Expected ASI-02 detection, got: {pattern_types}"

        # ASI-09 related
        assert 'agent_impersonation_risk' in pattern_types, \
            f"Expected ASI-09 impersonation detection, got: {pattern_types}"

    def test_secure_code_minimal_findings(self, scanner, tmp_path):
        """Test that secure code has minimal findings."""
        code = dedent('''
            from langchain.agents import AgentExecutor
            from langchain_core.tools import tool
            from langchain_core.messages import SystemMessage
            from langchain.callbacks import HumanApprovalCallbackHandler
            import re

            @tool
            def safe_calculator(expression: str) -> str:
                """Calculate math expressions safely"""
                if not isinstance(expression, str):
                    raise ValueError("Invalid type")
                if not re.match(r"^[0-9+\\-*/().\\s]+$", expression):
                    raise ValueError("Invalid characters")
                return str(eval(expression))

            system_msg = SystemMessage(
                content="You are a helpful AI assistant for math calculations."
            )

            executor = AgentExecutor(
                agent=agent,
                tools=[safe_calculator],
                max_iterations=5,
                max_execution_time=30,
                callbacks=[HumanApprovalCallbackHandler()]
            )
        ''')
        test_file = tmp_path / "secure_code.py"
        test_file.write_text(code)

        results = scanner.scan(test_file)

        patterns = results[0].dangerous_patterns

        # Filter to v0.3.0 ASI-02/09 specific patterns (excluding eval detection)
        # Note: eval() is ALWAYS flagged as unsafe - this is intentional behavior
        # The test verifies that OTHER ASI rules don't false positive
        asi_patterns = [
            p for p in patterns
            if p.get('type') in (
                'tool_no_input_validation',
                # 'tool_unrestricted_execution' - excluded since eval is always unsafe
                'missing_human_in_loop',
                'agent_impersonation_risk',
                'trust_boundary_violation'
            )
        ]

        # Secure code should have no false positive findings for the rules that
        # can be mitigated through proper configuration (not eval which is always unsafe)
        assert len(asi_patterns) == 0, \
            f"Secure code should not trigger ASI rules, got: {asi_patterns}"
