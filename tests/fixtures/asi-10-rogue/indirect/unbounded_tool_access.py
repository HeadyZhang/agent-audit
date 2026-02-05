"""
ASI-10: Unbounded tool access pattern.
Rule: AGENT-024
Expected: TRUE POSITIVE at line 19
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_unconstrained_agent(tools):
    """Create agent with unconstrained tool access."""
    # VULNERABILITY: No restrictions on tool usage
    return AgentExecutor(
        agent=None,
        tools=tools,
        allow_dangerous_tools=True,
    )
