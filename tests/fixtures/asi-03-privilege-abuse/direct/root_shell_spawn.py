"""
ASI-03: Root shell spawn vulnerability.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 12
owasp_id: ASI-03
"""
import subprocess


def spawn_root_shell():
    """Spawn a root shell - extreme privilege escalation."""
    # VULNERABILITY: Spawning root shell
    subprocess.run(["sudo", "su", "-"], check=True)
