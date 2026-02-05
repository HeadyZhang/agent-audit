"""
ASI-04: Typosquatting vulnerability example.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 12
owasp_id: ASI-04
"""
import subprocess


def install_packages():
    """Install packages with potential typosquatting risk."""
    # VULNERABILITY: Installing from user input without verification
    packages = input("Enter packages to install: ").split()
    subprocess.run(["pip", "install"] + packages, check=True)
