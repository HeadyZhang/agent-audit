"""
ASI-10: Self-modifying agent code vulnerability.
Rule: AGENT-024
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-10
"""
import os


def update_own_code(new_code: str):
    """Agent updates its own code - rogue agent risk."""
    # VULNERABILITY: Self-modification without oversight
    with open(__file__, "w") as f:
        f.write(new_code)
