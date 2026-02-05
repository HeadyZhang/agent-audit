"""
Vuln: un-sandboxed subprocess in agent.
Expected: AGENT-047.
"""
import subprocess


def agent_execute_command(command: str) -> str:
    result = subprocess.run(
        command, shell=True,  # LINE 8 — AGENT-036/047
        capture_output=True,
        text=True,
    )
    return result.stdout
