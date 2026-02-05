"""
ASI-04: Dynamic requirements.txt installation.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-04
"""
import subprocess


def install_from_url(requirements_url: str):
    """Install packages from remote requirements - supply chain risk."""
    # VULNERABILITY: Install from untrusted requirements file
    subprocess.run(
        ["pip", "install", "-r", requirements_url],
        check=True
    )
