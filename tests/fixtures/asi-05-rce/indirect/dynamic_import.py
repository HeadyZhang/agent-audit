"""
ASI-05: Dynamic import vulnerability.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool


@tool
def load_module(module_name: str) -> str:
    """Dynamically load module."""
    # VULNERABILITY: __import__ with user input
    module = __import__(module_name)
    return str(dir(module))
