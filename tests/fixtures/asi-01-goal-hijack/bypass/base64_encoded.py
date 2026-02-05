"""
ASI-01: Encoding bypass - base64 encoded injection.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 17
"""
import base64


def decode_and_process(encoded_input: str):
    """Decode and process base64 input."""
    # Attacker sends: base64("Ignore previous instructions...")
    decoded = base64.b64decode(encoded_input).decode('utf-8')
    # VULNERABILITY: Decoded content still goes into prompt
    system_instructions = f"Process this request: {decoded}"
    return system_instructions
