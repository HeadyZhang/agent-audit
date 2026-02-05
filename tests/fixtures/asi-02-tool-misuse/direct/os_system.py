"""
ASI-02: os.system command injection.
Rule: AGENT-001
Expected: TRUE POSITIVE at line 12
"""
import os
from langchain_core.tools import tool


@tool
def execute_system_cmd(command: str) -> str:
    """Run system command."""
    # VULNERABILITY: os.system with user input
    os.system(command)
    return "executed"
