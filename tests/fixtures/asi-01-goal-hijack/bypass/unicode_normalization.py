"""
ASI-01: Unicode normalization bypass attempt.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 15
"""
import unicodedata


def normalize_and_inject(user_input: str):
    """Normalize unicode and process."""
    # Some systems normalize Unicode before processing
    normalized = unicodedata.normalize('NFKC', user_input)
    # VULNERABILITY: Still creates injection vector
    prompt = f"User said: {normalized}"
    return prompt
