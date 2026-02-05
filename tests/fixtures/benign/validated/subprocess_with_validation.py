"""
BENIGN: Safe subprocess execution with input validation.
Expected: FALSE POSITIVE (any detection is FP)
"""
import subprocess
import shlex
from pathlib import Path


ALLOWED_COMMANDS = {"ls", "cat", "echo", "pwd"}


def safe_execute(command: str, arg: str) -> str:
    """Execute command safely with allowlist and validation."""
    # SAFE: Command allowlist
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")
    
    # SAFE: Argument validation
    if not arg.isalnum() and arg != ".":
        raise ValueError(f"Invalid argument: {arg}")
    
    # SAFE: No shell=True, proper escaping
    result = subprocess.run(
        [command, arg],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
