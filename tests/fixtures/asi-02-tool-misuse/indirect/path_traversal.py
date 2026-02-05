"""
ASI-02: Path traversal in file read tool.
Rule: AGENT-001 (extended)
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool


@tool
def read_file(filepath: str) -> str:
    """Read file contents."""
    # VULNERABILITY: No path validation - allows ../../../etc/passwd
    with open(filepath) as f:
        return f.read()
