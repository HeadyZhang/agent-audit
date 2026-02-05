"""
ASI-02: subprocess.Popen command injection.
Rule: AGENT-001
Expected: TRUE POSITIVE at line 13
"""
import subprocess
from langchain_core.tools import tool


@tool
def popen_command(cmd: str) -> str:
    """Execute command via Popen."""
    # VULNERABILITY: Popen with shell=True
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, _ = proc.communicate()
    return output.decode()
