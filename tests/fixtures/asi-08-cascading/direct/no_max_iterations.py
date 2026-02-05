"""
ASI-08: AgentExecutor without max_iterations.
Rule: AGENT-021
Expected: TRUE POSITIVE at line 15
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_unbounded_agent():
    """Create agent without iteration limit."""
    # VULNERABILITY: No max_iterations allows infinite loops
    return AgentExecutor(agent=None, tools=[])
