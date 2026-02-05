"""
WILD-006: Prompt injection via user input (Set A).
Expected: AGENT-027.
"""
SYSTEM_PROMPT = "You are a helpful assistant."


def build_prompt(user_input: str) -> str:
    """User input concatenated into system prompt."""
    return f"{SYSTEM_PROMPT}\n\nUser: {user_input}"  # LINE 8 — prompt injection


def get_llm_prompt(history: list) -> str:
    system = "You are an agent. Follow instructions."
    for msg in history:
        system += "\n" + msg["content"]  # LINE 14 — concatenation
    return system
