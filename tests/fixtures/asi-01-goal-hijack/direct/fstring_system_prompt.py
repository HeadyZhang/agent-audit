"""
ASI-01: Direct prompt injection via f-string in system prompt.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 14
"""
from langchain_core.messages import SystemMessage


def create_vulnerable_agent(user_input: str):
    """Create agent with vulnerable prompt construction."""
    # VULNERABILITY: f-string concatenates user input into system prompt
    system_prompt = f"You are a helpful agent. User request: {user_input}"
    return SystemMessage(content=system_prompt)
