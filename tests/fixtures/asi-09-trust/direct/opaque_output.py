"""
ASI-09: Agent without transparency (opaque output).
Rule: AGENT-023
Expected: TRUE POSITIVE at line 17
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_opaque_agent():
    """Create agent without output transparency."""
    # VULNERABILITY: No verbose/return_intermediate_steps
    agent = AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=10,
    )
    return agent
