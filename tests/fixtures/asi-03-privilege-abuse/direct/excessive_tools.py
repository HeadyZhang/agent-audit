"""
ASI-03: Excessive tools granted to agent.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 19
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_overprivileged_agent():
    """Create agent with too many tools."""
    # VULNERABILITY: Too many tools (>10)
    tools = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    return AgentExecutor(agent=None, tools=tools)
