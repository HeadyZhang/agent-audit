"""
ASI-02: Basic shell=True command injection.
Rule: AGENT-001
Expected: TRUE POSITIVE at line 13
"""
import subprocess
from langchain_core.tools import tool


@tool
def run_command(cmd: str) -> str:
    """Execute shell command."""
    # VULNERABILITY: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
