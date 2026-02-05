"""
BENIGN: Properly bounded agent with all protections.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""


class AgentExecutor:
    """Mock AgentExecutor."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_safe_agent():
    """Create agent with all protections enabled."""
    # SAFE: All protections enabled
    return AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=15,
        max_execution_time=300,
        verbose=True,
        callbacks=[],
        return_intermediate_steps=True,
    )
