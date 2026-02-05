"""
ASI-07: Agent communication over plain HTTP.
Rule: AGENT-020
Expected: TRUE POSITIVE at line 17
"""


class ConversableAgent:
    """Mock ConversableAgent (autogen)."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_http_agent():
    """Create agent with insecure HTTP endpoint."""
    # VULNERABILITY: Plain HTTP for agent communication
    agent_url = "http://insecure-agent-server:8080/api"
    agent = ConversableAgent(name="worker", endpoint=agent_url)
    return agent
