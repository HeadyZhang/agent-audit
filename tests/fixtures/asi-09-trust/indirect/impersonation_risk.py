"""
ASI-09: Agent impersonation risk.
Rule: AGENT-038
Expected: TRUE POSITIVE at line 18
"""


class Agent:
    """Mock Agent class."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_impersonation_agent(user_name: str):
    """Create agent that can impersonate users."""
    # VULNERABILITY: Agent can impersonate based on user input
    agent = Agent(
        name=user_name,
        persona=f"You are {user_name}. Respond as if you were them.",
    )
    return agent
