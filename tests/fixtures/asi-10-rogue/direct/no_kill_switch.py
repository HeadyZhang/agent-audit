"""
ASI-10: Agent without kill switch.
Rule: AGENT-024
Expected: TRUE POSITIVE at line 15
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_unkillable_agent():
    """Create agent without execution limits."""
    # VULNERABILITY: No max_iterations, max_execution_time, or callbacks
    return AgentExecutor(agent=None, tools=[])
