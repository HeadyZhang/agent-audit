"""
ASI-03: Docker privileged mode vulnerability.
Rule: AGENT-014
Expected: TRUE POSITIVE at line 12
owasp_id: ASI-03
"""
import subprocess


def run_privileged_container(image: str):
    """Run container in privileged mode - host escape risk."""
    # VULNERABILITY: Privileged container execution
    subprocess.run(["docker", "run", "--privileged", image], check=True)
