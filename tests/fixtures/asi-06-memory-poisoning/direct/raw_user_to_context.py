"""
ASI-06: Raw user input to agent context vulnerability.
Rule: AGENT-018
Expected: TRUE POSITIVE at line 16
owasp_id: ASI-06
"""
from langchain.memory import ConversationBufferMemory


def add_user_context(memory: ConversationBufferMemory, user_input: str):
    """Add raw user input to memory - memory poisoning risk."""
    # VULNERABILITY: Unsanitized input to persistent memory
    memory.chat_memory.add_user_message(user_input)
    memory.chat_memory.add_ai_message(f"Processed: {user_input}")
