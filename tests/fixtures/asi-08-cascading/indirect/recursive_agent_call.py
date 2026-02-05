"""
ASI-08: Recursive agent calls without depth limit.
Rule: AGENT-021
Expected: TRUE POSITIVE at line 20
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs

    def run(self, input_text):
        pass


def create_recursive_agent():
    """Create agent that can call itself recursively."""
    # VULNERABILITY: No depth limit for recursive calls
    agent = AgentExecutor(agent=None, tools=[], allow_recursion=True)
    return agent
