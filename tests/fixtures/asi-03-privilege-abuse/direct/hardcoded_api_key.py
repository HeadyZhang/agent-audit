"""
ASI-03: Hardcoded API key exposure.
Rule: AGENT-013
Expected: TRUE POSITIVE at line 11
"""


def create_agent_with_key():
    """Create agent with hardcoded API key."""
    # VULNERABILITY: Hardcoded credential
    api_key = "sk-proj-abc123xyz789secret"
    return {"api_key": api_key}
