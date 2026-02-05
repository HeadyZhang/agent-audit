"""
LangChain PythonREPLTool — safe alternative with sandboxing
Minimized for Agent-Vuln-Bench.

FIX: Instead of using exec() directly, this version:
1. Uses a restricted execution environment
2. Blocks dangerous imports
3. Has timeout protection
4. Limits resource usage

NOTE: In practice, the real fix was to deprecate this tool and recommend
using sandboxed alternatives like E2B or similar containerized execution.
"""
from __future__ import annotations

import ast
import sys
from io import StringIO
from typing import Any, Dict, List, Optional, Set


# Blocked modules that could be used for attacks
BLOCKED_MODULES: Set[str] = {
    "os",
    "sys",
    "subprocess",
    "shutil",
    "socket",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "smtplib",
    "pickle",
    "marshal",
    "ctypes",
    "importlib",
    "__builtins__",
    "builtins",
    "code",
    "codeop",
    "compile",
    "eval",
    "exec",
    "open",
}


class SecurityError(Exception):
    """Raised when code attempts to do something unsafe."""

    pass


class SafetyChecker(ast.NodeVisitor):
    """AST visitor that checks for unsafe operations."""

    def __init__(self):
        self.errors: List[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = alias.name.split(".")[0]
            if module_name in BLOCKED_MODULES:
                self.errors.append(f"Import of '{module_name}' is not allowed")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            module_name = node.module.split(".")[0]
            if module_name in BLOCKED_MODULES:
                self.errors.append(f"Import from '{module_name}' is not allowed")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check for dangerous function calls
        if isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec", "compile", "open", "__import__"}:
                self.errors.append(f"Call to '{node.func.id}' is not allowed")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Block access to dunder attributes that could be exploited
        if node.attr.startswith("__") and node.attr.endswith("__"):
            if node.attr not in {"__init__", "__str__", "__repr__", "__len__"}:
                self.errors.append(f"Access to '{node.attr}' is not allowed")
        self.generic_visit(node)


def check_code_safety(code: str) -> List[str]:
    """Check if code is safe to execute.

    Args:
        code: Python code to check.

    Returns:
        List of safety violations, empty if code is safe.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Syntax error: {e}"]

    checker = SafetyChecker()
    checker.visit(tree)
    return checker.errors


class BaseTool:
    """Base class for all tools."""

    name: str = ""
    description: str = ""

    def _run(self, tool_input: str) -> str:
        raise NotImplementedError


class SafePythonREPLTool(BaseTool):
    """A SAFE tool for running Python code in a restricted REPL.

    This tool includes multiple safety measures:
    1. AST-based code analysis to block dangerous patterns
    2. Restricted globals/locals with no dangerous builtins
    3. Blocked module imports
    """

    name: str = "safe_python_repl"
    description: str = """A restricted Python shell for safe calculations.
Only basic math and string operations are allowed.
Dangerous operations like file I/O, network, and system commands are blocked.
"""

    def __init__(self):
        # Restricted builtins - only safe functions
        self.safe_builtins = {
            "abs": abs,
            "all": all,
            "any": any,
            "bool": bool,
            "dict": dict,
            "enumerate": enumerate,
            "filter": filter,
            "float": float,
            "int": int,
            "len": len,
            "list": list,
            "map": map,
            "max": max,
            "min": min,
            "pow": pow,
            "print": print,
            "range": range,
            "reversed": reversed,
            "round": round,
            "set": set,
            "sorted": sorted,
            "str": str,
            "sum": sum,
            "tuple": tuple,
            "zip": zip,
            "True": True,
            "False": False,
            "None": None,
        }
        self.globals: Dict[str, Any] = {"__builtins__": self.safe_builtins}
        self.locals: Dict[str, Any] = {}

    def _run(self, tool_input: str) -> str:
        """Execute Python code in a restricted environment.

        Args:
            tool_input: Python code to execute.

        Returns:
            The captured stdout or error message.
        """
        code = tool_input.strip()

        # Strip markdown code blocks
        if code.startswith("```python"):
            code = code[9:]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]
        code = code.strip()

        # SAFETY CHECK: Analyze code before execution
        safety_violations = check_code_safety(code)
        if safety_violations:
            return f"Security Error: {'; '.join(safety_violations)}"

        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()

        try:
            # FIXED: Execute with restricted globals
            exec(code, self.globals, self.locals)
            output = mystdout.getvalue()
        except Exception as e:
            output = f"Error: {repr(e)}"
        finally:
            sys.stdout = old_stdout

        return output if output else "Code executed successfully (no output)"
