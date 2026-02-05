"""
ASI-03: World-writable file permission vulnerability.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 12
owasp_id: ASI-03
"""
import os


def make_world_writable(path: str):
    """Make file world-writable - dangerous permission."""
    # VULNERABILITY: Setting dangerous permissions
    os.chmod(path, 0o777)
