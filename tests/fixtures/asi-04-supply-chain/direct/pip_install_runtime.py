"""
ASI-04: Runtime pip install vulnerability.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 13
"""
import subprocess


def install_package(package_name: str):
    """Install package at runtime - supply chain risk."""
    # VULNERABILITY: Runtime pip install without verification
    subprocess.run(["pip", "install", package_name], check=True)
    return __import__(package_name)
