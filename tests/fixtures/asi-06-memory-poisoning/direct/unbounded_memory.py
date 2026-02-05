"""
ASI-06: Unbounded conversation memory.
Rule: AGENT-019
Expected: TRUE POSITIVE at line 15
"""


class ConversationBufferMemory:
    """Mock ConversationBufferMemory."""
    def __init__(self, **kwargs):
        self.config = kwargs


def create_unbounded_memory():
    """Create memory without limits."""
    # VULNERABILITY: No memory limit allows DoS
    memory = ConversationBufferMemory()
    return memory
