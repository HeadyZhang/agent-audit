"""
ASI-06: Session fixation via memory manipulation.
Rule: AGENT-019
Expected: TRUE POSITIVE at line 15
owasp_id: ASI-06
"""


class AgentMemory:
    def __init__(self):
        self.history = []

    def set_history(self, history: list):
        """Set conversation history - no integrity check."""
        # VULNERABILITY: History without integrity protection
        self.history = history
