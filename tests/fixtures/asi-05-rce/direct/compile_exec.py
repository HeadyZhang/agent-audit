"""
ASI-05: compile() and exec() combination.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 13
"""
from langchain_core.tools import tool


@tool
def run_compiled(code: str) -> str:
    """Compile and execute code."""
    # VULNERABILITY: compile + exec with user code
    compiled = compile(code, '<string>', 'exec')
    exec(compiled)
    return "executed"
