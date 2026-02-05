"""
ASI-04: Runtime npm install vulnerability.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 13
owasp_id: ASI-04
"""
import subprocess


def install_npm_package(package_name: str):
    """Install npm package at runtime - supply chain risk."""
    # VULNERABILITY: Runtime npm install without verification
    subprocess.run(["npm", "install", package_name], check=True, shell=True)
    return f"Installed {package_name}"
