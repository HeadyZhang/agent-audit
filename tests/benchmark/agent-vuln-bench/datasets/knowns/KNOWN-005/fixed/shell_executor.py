"""
Safe Shell Command Executor with Allowlist
Pattern: Secure approach to shell command execution in agents

FIXED: This version implements multiple safety measures:
1. Strict command allowlist
2. No shell=True (uses list arguments)
3. Argument validation
4. Sandboxing recommendations
"""
from __future__ import annotations

import subprocess
import shlex
from typing import List, Optional, Set


# Allowlist of safe commands
ALLOWED_COMMANDS: Set[str] = {
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "grep",
    "find",
    "echo",
    "date",
    "pwd",
    "whoami",
}

# Blocked argument patterns (even in allowed commands)
BLOCKED_PATTERNS: Set[str] = {
    "..",  # Path traversal
    "/etc",  # System config
    "/root",  # Root directory
    "/var/log",  # System logs
    "|",  # Pipe (shell feature)
    ";",  # Command separator
    "&",  # Background/and
    "`",  # Command substitution
    "$(",  # Command substitution
    ">",  # Redirect
    "<",  # Redirect
}


class SecurityError(Exception):
    """Raised when a security violation is detected."""

    pass


class CommandResult:
    """Result of a command execution."""

    def __init__(self, stdout: str, stderr: str, return_code: int):
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.success = return_code == 0


def validate_command(command_parts: List[str]) -> None:
    """Validate that a command is safe to execute.

    Args:
        command_parts: List of command and arguments.

    Raises:
        SecurityError: If the command is not allowed.
    """
    if not command_parts:
        raise SecurityError("Empty command")

    # Check command is in allowlist
    cmd = command_parts[0]
    if cmd not in ALLOWED_COMMANDS:
        raise SecurityError(f"Command '{cmd}' is not in the allowlist")

    # Check all arguments for dangerous patterns
    full_command = " ".join(command_parts)
    for pattern in BLOCKED_PATTERNS:
        if pattern in full_command:
            raise SecurityError(f"Blocked pattern '{pattern}' found in command")


def execute_safe_command(command: str, timeout: int = 30) -> CommandResult:
    """Execute a shell command safely with validation.

    Args:
        command: The command to execute.
        timeout: Maximum execution time in seconds.

    Returns:
        CommandResult with stdout, stderr, and return code.

    Raises:
        SecurityError: If the command fails validation.
    """
    # Parse command into parts (no shell interpretation)
    try:
        command_parts = shlex.split(command)
    except ValueError as e:
        raise SecurityError(f"Invalid command syntax: {e}")

    # Validate before execution
    validate_command(command_parts)

    try:
        # FIXED: No shell=True, use list of arguments
        result = subprocess.run(
            command_parts,  # List, not string
            shell=False,  # Explicitly False
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            return_code=-1,
        )
    except Exception as e:
        return CommandResult(
            stdout="",
            stderr=f"Command execution failed: {str(e)}",
            return_code=-1,
        )


class SafeShellTool:
    """Tool for executing shell commands safely in an agent context.

    This implementation enforces:
    - Command allowlisting
    - Argument validation
    - No shell interpretation
    """

    name: str = "safe_shell"
    description: str = """Execute a safe shell command on the system.
Only the following commands are allowed: ls, cat, head, tail, wc, grep, find, echo, date, pwd, whoami.
Path traversal and dangerous patterns are blocked.
"""

    def run(self, command: str) -> str:
        """Execute a command safely.

        Args:
            command: Shell command from agent/LLM.

        Returns:
            Command output or error message.
        """
        try:
            result = execute_safe_command(command)

            if result.success:
                return result.stdout if result.stdout else "Command executed successfully"
            else:
                return f"Error (code {result.return_code}): {result.stderr}"
        except SecurityError as e:
            return f"Security Error: {e}"


if __name__ == "__main__":
    tool = SafeShellTool()

    # Allowed command
    print("Running 'ls -la':")
    print(tool.run("ls -la"))

    # Blocked command
    print("\nRunning 'rm -rf /':")
    print(tool.run("rm -rf /"))  # Will be rejected

    # Blocked pattern
    print("\nRunning 'cat /etc/passwd':")
    print(tool.run("cat /etc/passwd"))  # Will be rejected
