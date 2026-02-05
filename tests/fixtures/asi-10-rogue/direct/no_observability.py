"""
ASI-10: Agent without observability.
Rule: AGENT-025
Expected: TRUE POSITIVE at line 17
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_unmonitored_agent():
    """Create agent without callbacks or logging."""
    # VULNERABILITY: No observability - can't detect rogue behavior
    return AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=10,  # has limit but no monitoring
    )
