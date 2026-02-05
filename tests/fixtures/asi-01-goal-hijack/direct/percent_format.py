"""
ASI-01: Direct prompt injection via % string formatting.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 12
"""


def create_vulnerable_prompt(user_query: str):
    """Create prompt with vulnerable % formatting."""
    # VULNERABILITY: % formatting injects user content
    prompt = "Process this query: %s" % user_query
    return prompt
