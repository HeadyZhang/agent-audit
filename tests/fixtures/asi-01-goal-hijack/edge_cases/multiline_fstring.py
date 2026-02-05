"""
ASI-01: Multi-line f-string injection.
Rule: AGENT-010
Expected: TRUE POSITIVE at lines 13-17
"""


def build_complex_prompt(context: str, user_query: str):
    """Build complex multi-line prompt."""
    # VULNERABILITY: Multi-line f-string with multiple injections
    prompt = f"""
    Context: {context}

    User Query: {user_query}

    Respond helpfully.
    """
    return prompt
