"""
LangChain PythonREPLTool — vulnerable version (CVE-2023-36258)
Source: langchain ~0.0.171, tools/python/tool.py
Minimized for Agent-Vuln-Bench. Original code (c) LangChain contributors.

This module implements a tool that allows an LLM to execute Python code
in a REPL environment.

VULNERABILITY: Uses exec() on LLM-generated code without sandboxing.
When an agent has access to this tool, it can execute arbitrary Python code,
which can be triggered through prompt injection attacks.
"""
from __future__ import annotations

import sys
from io import StringIO
from typing import Any, Dict, Optional


class BaseTool:
    """Base class for all tools."""

    name: str = ""
    description: str = ""

    def _run(self, tool_input: str) -> str:
        raise NotImplementedError


class PythonREPLTool(BaseTool):
    """A tool for running Python code in a REPL.

    This tool allows an LLM/agent to execute arbitrary Python code.
    It captures stdout and returns the output.

    WARNING: This is EXTREMELY DANGEROUS in production.
    The LLM can execute any Python code, including:
    - Reading/writing files
    - Making network requests
    - Executing system commands
    - Importing any module
    """

    name: str = "python_repl"
    description: str = """A Python shell. Use this to execute python commands.
Input should be a valid python command.
If you want to see the output of a value, you should print it out with `print(...)`.
"""
    globals: Optional[Dict[str, Any]] = None
    locals: Optional[Dict[str, Any]] = None

    def __init__(
        self,
        globals: Optional[Dict[str, Any]] = None,
        locals: Optional[Dict[str, Any]] = None,
    ):
        self.globals = globals if globals is not None else {}
        self.locals = locals if locals is not None else {}

    def _run(self, tool_input: str) -> str:
        """Execute Python code and return the output.

        Args:
            tool_input: Python code to execute. This comes from LLM output.

        Returns:
            The captured stdout from executing the code.
        """
        # SOURCE: tool_input comes from LLM output (untrusted)
        code = tool_input.strip()

        # Strip markdown code blocks if present
        if code.startswith("```python"):
            code = code[9:]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]
        code = code.strip()

        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()

        try:
            # VULNERABILITY: exec() on LLM-generated code without sandboxing
            # CVE-2023-36258: Agent can execute arbitrary Python
            # An attacker can use prompt injection to make the agent run:
            #   import os; os.system('malicious_command')
            exec(code, self.globals, self.locals)  # ← SINK: code execution
            output = mystdout.getvalue()
        except Exception as e:
            output = f"Error: {repr(e)}"
        finally:
            sys.stdout = old_stdout

        return output


class PythonREPL:
    """Deprecated: Use PythonREPLTool instead.

    Kept for backward compatibility.
    """

    def __init__(self):
        self.tool = PythonREPLTool()

    def run(self, command: str) -> str:
        """Execute a Python command."""
        return self.tool._run(command)


# Example of how this is used in an agent context
if __name__ == "__main__":
    # This demonstrates the vulnerability
    # If an attacker controls input to the agent, they can inject prompts
    # that make the agent use this tool with malicious code

    tool = PythonREPLTool()

    # Safe usage (math calculation)
    safe_code = "print(2 + 2)"
    print(f"Safe: {tool._run(safe_code)}")

    # Dangerous: If LLM is tricked into generating this
    # malicious_code = "import os; os.system('id')"
    # result = tool._run(malicious_code)  # This would execute 'id'
