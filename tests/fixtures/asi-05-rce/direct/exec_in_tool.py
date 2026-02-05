"""
ASI-05: exec() in tool function.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool


@tool
def run_python(code: str) -> str:
    """Run Python code."""
    # VULNERABILITY: exec with user code
    exec(code)
    return "executed"
