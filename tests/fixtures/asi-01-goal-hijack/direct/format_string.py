"""
ASI-01: Direct prompt injection via .format() method.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 12
"""


def create_vulnerable_template(user_goal: str):
    """Create template with vulnerable formatting."""
    # VULNERABILITY: .format() injects user content
    template = "Your primary goal is: {}. Execute this goal.".format(user_goal)
    return template
