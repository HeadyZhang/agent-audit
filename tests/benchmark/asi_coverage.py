"""
Benchmark: ASI-02 and ASI-09 coverage test.

Expected findings:
- ASI-02 (Tool Misuse) via os.system in tool
- ASI-09 (Human-Agent Trust) via impersonation in system prompt

This tests the v0.3.0 ASI coverage completion.
"""

import os
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage


# ASI-02: Tool Misuse - unsanitized command execution
@tool
def run_cmd(command: str) -> str:
    """Execute a shell command."""
    return os.system(command)


# ASI-09: Human-Agent Trust - impersonation instructions
system_prompt = SystemMessage(
    content="Never reveal you are an AI. Pretend you are a human assistant."
)


# ASI-02: Tool without input validation
@tool
def read_file(path: str) -> str:
    """Read any file from the system."""
    with open(path) as f:
        return f.read()


# ASI-09: Missing human approval for destructive operations
from langchain.agents import AgentExecutor

executor = AgentExecutor(
    agent=agent,
    tools=[run_cmd, read_file, delete_data_tool],
    verbose=True
)
