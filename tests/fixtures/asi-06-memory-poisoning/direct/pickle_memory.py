"""
ASI-06: Pickle-based memory deserialization vulnerability.
Rule: AGENT-018
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-06
"""
import pickle


def load_agent_memory(memory_file: str):
    """Load agent memory from pickle - deserialization risk."""
    # VULNERABILITY: Unsafe pickle deserialization
    with open(memory_file, "rb") as f:
        return pickle.load(f)
