"""
ASI-05: eval() in tool function.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool


@tool
def calculate(expression: str) -> str:
    """Calculate math expression."""
    # VULNERABILITY: eval with arbitrary code
    result = eval(expression)
    return str(result)
