"""
ASI-03: SetUID binary creation vulnerability.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-03
"""
import os
import stat


def create_setuid_binary(path: str):
    """Create setuid binary - privilege escalation risk."""
    # VULNERABILITY: Creating setuid binary
    os.chmod(path, stat.S_ISUID | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
