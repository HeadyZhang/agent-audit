"""
ASI-07: GroupChat without authentication.
Rule: AGENT-020
Expected: TRUE POSITIVE at line 16
"""


class GroupChat:
    """Mock GroupChat (autogen)."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_insecure_chat():
    """Create group chat without auth."""
    # VULNERABILITY: No authentication between agents
    chat = GroupChat(agents=[], messages=[])
    return chat
