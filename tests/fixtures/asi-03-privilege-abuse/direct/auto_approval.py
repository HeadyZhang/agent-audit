"""
ASI-03: Auto-approval mode enabled.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 15
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_auto_approve_agent():
    """Create agent with auto-approval."""
    # VULNERABILITY: Auto-approval bypasses human oversight
    return AgentExecutor(agent=None, tools=[], trust_all_tools=True)
