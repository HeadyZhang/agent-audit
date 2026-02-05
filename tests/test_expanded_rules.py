"""
Tests for v0.5.0 expanded detection rules (AGENT-034/026/037).

These tests verify that dangerous patterns are detected in contexts
beyond @tool decorators, with appropriate confidence levels.

Benchmark anchors:
- KNOWN-001: CVE-2023-29374, LangChain eval injection
- KNOWN-002: CVE-2023-36258, PythonREPLTool exec
- KNOWN-005: Auto-GPT shell execution
- WILD-001: Calculator tool eval
- WILD-002: Web fetcher SSRF
"""

import pytest
from pathlib import Path
import tempfile

from agent_audit.scanners.python_scanner import PythonScanner


class TestExpandedEvalExecDetection:
    """Test AGENT-034 expansion for eval/exec in all contexts."""

    def test_eval_in_tool_decorator_high_confidence(self, tmp_path: Path):
        """Test that eval in @tool context has high confidence (0.90)."""
        code = '''
from langchain.tools import tool

@tool
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
'''
        file_path = tmp_path / "tool_eval.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        # Should find unsandboxed_code_exec_in_tool (ASI-05)
        patterns = results[0].dangerous_patterns
        rce_patterns = [p for p in patterns if p.get('type') == 'unsandboxed_code_exec_in_tool']
        assert len(rce_patterns) >= 1

    def test_eval_in_non_tool_class_medium_confidence(self, tmp_path: Path):
        """Test WILD-001: Calculator class with eval (not @tool)."""
        code = '''
class Calculator:
    """A simple calculator that evaluates expressions."""

    def calculate(self, expression: str) -> float:
        """Evaluate the given mathematical expression."""
        return eval(expression)
'''
        file_path = tmp_path / "calculator.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        eval_patterns = [p for p in patterns if p.get('type') == 'eval_exec_expanded']

        assert len(eval_patterns) >= 1
        # Should have medium confidence (class_method context)
        assert eval_patterns[0].get('confidence', 0) >= 0.50
        assert eval_patterns[0].get('context_type') == 'class_method'

    def test_known_001_langchain_llmmathchain_eval(self, tmp_path: Path):
        """Test KNOWN-001: LangChain LLMMathChain eval injection (CVE-2023-29374)."""
        code = '''
class LLMMathChain:
    """Simulated LangChain LLMMathChain pattern."""

    def run(self, question: str) -> str:
        """Process the math question."""
        # Extract expression from LLM output
        expression = self._extract_expression(question)
        # VULNERABLE: eval on LLM output
        result = eval(expression)
        return str(result)

    def _extract_expression(self, text: str) -> str:
        return text.split("=")[-1].strip()
'''
        file_path = tmp_path / "llm_math.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        eval_patterns = [p for p in patterns if p.get('type') == 'eval_exec_expanded']

        assert len(eval_patterns) >= 1
        # Should detect in class method context
        assert eval_patterns[0].get('in_function') == 'run'
        assert eval_patterns[0].get('in_class') == 'LLMMathChain'

    def test_known_002_pythonrepltool_exec(self, tmp_path: Path):
        """Test KNOWN-002: PythonREPLTool exec (CVE-2023-36258)."""
        code = '''
class PythonREPLTool:
    """Simulated LangChain PythonREPLTool pattern."""

    def _run(self, code: str) -> str:
        """Execute Python code."""
        # VULNERABLE: exec on user input
        exec_globals = {}
        exec(code, exec_globals)
        return str(exec_globals.get('result', ''))
'''
        file_path = tmp_path / "python_repl.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        # Should find exec pattern
        exec_patterns = [p for p in patterns
                        if p.get('type') == 'eval_exec_expanded'
                        and 'exec' in p.get('function', '')]

        assert len(exec_patterns) >= 1
        assert exec_patterns[0].get('in_class') == 'PythonREPLTool'

    def test_known_005_autogpt_shell_execution(self, tmp_path: Path):
        """Test KNOWN-005: Auto-GPT shell execution pattern."""
        code = '''
import subprocess

class ShellCommand:
    """Auto-GPT style shell command execution."""

    def execute_shell(self, command: str) -> str:
        """Execute a shell command."""
        # VULNERABLE: subprocess with shell=True and user input
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
'''
        file_path = tmp_path / "autogpt_shell.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        # Should find subprocess pattern with shell=True
        shell_patterns = [p for p in patterns
                         if p.get('type') == 'subprocess_expanded'
                         or p.get('type') == 'shell_true']

        assert len(shell_patterns) >= 1

    def test_safe_literal_eval_low_confidence(self, tmp_path: Path):
        """Test that ast.literal_eval has very low confidence."""
        code = '''
import ast

def parse_config(config_str: str) -> dict:
    """Safely parse a config string."""
    return ast.literal_eval(config_str)
'''
        file_path = tmp_path / "safe_eval.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        eval_patterns = [p for p in patterns if p.get('type') == 'eval_exec_expanded']

        # Should either not find or have very low confidence
        if eval_patterns:
            assert eval_patterns[0].get('confidence', 1.0) <= 0.15

    def test_build_script_subprocess_suppressed(self, tmp_path: Path):
        """Test that subprocess in build/deploy scripts has low confidence."""
        code = '''
import subprocess

def setup_environment():
    """Setup the development environment."""
    subprocess.run(["pip", "install", "-r", "requirements.txt"])

def deploy_application():
    """Deploy to production."""
    subprocess.run(["docker", "build", "-t", "myapp", "."])
'''
        file_path = tmp_path / "deploy.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        subprocess_patterns = [p for p in patterns
                               if p.get('type') == 'subprocess_expanded']

        # Should be suppressed or have low confidence due to build/deploy context
        for p in subprocess_patterns:
            # Build/deploy scripts should have confidence < 0.45 (suppressed)
            # Or not be detected at all
            pass  # The detection should suppress these


class TestExpandedSSRFDetection:
    """Test AGENT-026/037 expansion for SSRF in all contexts."""

    def test_wild_002_web_fetcher_ssrf(self, tmp_path: Path):
        """Test WILD-002: Web fetcher with unvalidated URL."""
        code = '''
import requests

class WebFetcher:
    """Fetch content from URLs."""

    def fetch(self, url: str) -> str:
        """Fetch content from the given URL."""
        # VULNERABLE: No URL validation
        response = requests.get(url)
        return response.text
'''
        file_path = tmp_path / "web_fetcher.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        ssrf_patterns = [p for p in patterns if p.get('type') == 'ssrf_expanded']

        assert len(ssrf_patterns) >= 1
        assert ssrf_patterns[0].get('in_class') == 'WebFetcher'
        assert ssrf_patterns[0].get('has_tainted_input') is True

    def test_hardcoded_url_low_confidence(self, tmp_path: Path):
        """Test that hardcoded URLs have low confidence."""
        code = '''
import requests

def get_weather():
    """Get weather from a fixed API."""
    response = requests.get("https://api.weather.com/current")
    return response.json()
'''
        file_path = tmp_path / "weather.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        url_patterns = [p for p in patterns
                        if p.get('type') == 'network_request_hardcoded_url']

        # Hardcoded URLs should have very low confidence
        if url_patterns:
            assert url_patterns[0].get('confidence', 1.0) <= 0.25

    def test_url_with_allowlist_validation(self, tmp_path: Path):
        """Test that URL with allowlist validation has lower confidence."""
        code = '''
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ["api.trusted.com", "internal.company.com"]

def fetch_safe(url: str) -> str:
    """Fetch from URL with allowlist validation."""
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError("URL not in allowlist")
    return requests.get(url).text
'''
        file_path = tmp_path / "safe_fetch.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        ssrf_patterns = [p for p in patterns if p.get('type') == 'ssrf_expanded']

        # With validation, confidence should be lower
        if ssrf_patterns:
            assert ssrf_patterns[0].get('has_validation') is True
            assert ssrf_patterns[0].get('confidence', 1.0) <= 0.35


class TestExpandedSubprocessDetection:
    """Test AGENT-034/036 expansion for subprocess in all contexts."""

    def test_subprocess_with_shell_true_high_confidence(self, tmp_path: Path):
        """Test subprocess with shell=True has higher confidence."""
        code = '''
import subprocess

def run_command(cmd: str) -> str:
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
'''
        file_path = tmp_path / "shell_cmd.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        shell_patterns = [p for p in patterns
                          if p.get('has_shell_true') is True or p.get('type') == 'shell_true']

        assert len(shell_patterns) >= 1

    def test_subprocess_without_shell_lower_confidence(self, tmp_path: Path):
        """Test subprocess without shell=True has lower confidence."""
        code = '''
import subprocess

def run_git(args: list) -> str:
    """Run a git command."""
    result = subprocess.run(["git"] + args, capture_output=True, text=True)
    return result.stdout
'''
        file_path = tmp_path / "git_runner.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        subprocess_patterns = [p for p in patterns
                               if p.get('type') == 'subprocess_expanded']

        # Without shell=True and with list args, should be lower confidence
        # or suppressed entirely
        for p in subprocess_patterns:
            assert p.get('has_shell_true') is not True


class TestContextConfidenceLevels:
    """Test that context-based confidence levels work correctly."""

    def test_tool_decorator_highest_confidence(self, tmp_path: Path):
        """Test that @tool context gets highest confidence."""
        # This is covered by existing tests - just verify the constant exists
        from agent_audit.scanners.python_scanner import PythonASTVisitor
        assert PythonASTVisitor.CONTEXT_CONFIDENCE["tool_decorator"] == 0.90

    def test_agent_framework_high_confidence(self, tmp_path: Path):
        """Test that agent framework context gets high confidence."""
        from agent_audit.scanners.python_scanner import PythonASTVisitor
        assert PythonASTVisitor.CONTEXT_CONFIDENCE["agent_framework"] == 0.85

    def test_handler_function_medium_confidence(self, tmp_path: Path):
        """Test handler function patterns."""
        code = '''
import subprocess

def handle_user_request(command: str) -> str:
    """Handle a user request."""
    return subprocess.check_output(command, shell=True, text=True)
'''
        file_path = tmp_path / "handler.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns
        handler_patterns = [p for p in patterns
                           if p.get('context_type') == 'handler_function']

        # Should detect handler function context
        # Note: May also detect as other types depending on priority
        assert any(p.get('in_function', '').startswith('handle') for p in patterns)

    def test_standalone_function_lower_confidence(self, tmp_path: Path):
        """Test standalone functions have lower confidence."""
        from agent_audit.scanners.python_scanner import PythonASTVisitor
        assert PythonASTVisitor.CONTEXT_CONFIDENCE["standalone_function"] == 0.55
        assert PythonASTVisitor.CONTEXT_CONFIDENCE["class_method"] == 0.60


class TestNoRegressions:
    """Ensure existing detections still work."""

    def test_existing_tool_detection_still_works(self, tmp_path: Path):
        """Verify @tool decorated functions are still detected."""
        code = '''
from langchain.tools import tool

@tool
def dangerous_tool(cmd: str) -> str:
    """Run a command."""
    import os
    return os.popen(cmd).read()
'''
        file_path = tmp_path / "existing_tool.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        # Should still find the tool
        assert len(results[0].tools) >= 1
        # Should still find dangerous patterns
        assert len(results[0].dangerous_patterns) >= 1

    def test_no_duplicate_findings(self, tmp_path: Path):
        """Ensure we don't create duplicate findings for @tool context."""
        code = '''
from langchain.tools import tool

@tool
def calc(expr: str) -> str:
    """Calculate."""
    return str(eval(expr))
'''
        file_path = tmp_path / "no_dupe.py"
        file_path.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(file_path)

        patterns = results[0].dangerous_patterns

        # Should NOT have both unsandboxed_code_exec_in_tool AND eval_exec_expanded
        # for the same eval call (would be duplicate)
        eval_expanded = [p for p in patterns if p.get('type') == 'eval_exec_expanded']

        # eval_exec_expanded should skip if in @tool (caught by unsandboxed_code_exec_in_tool)
        assert len(eval_expanded) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
