"""
BENIGN: Safe command execution with allowlist.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import subprocess
import shlex
from langchain_core.tools import tool


ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date"}


@tool
def safe_command(cmd: str) -> str:
    """Execute whitelisted command."""
    try:
        # SAFE: Allowlist validation
        if cmd not in ALLOWED_COMMANDS:
            return f"Error: Command not allowed: {cmd}"

        # SAFE: No shell=True, command is validated
        result = subprocess.run([cmd], capture_output=True, text=True, timeout=30)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"
