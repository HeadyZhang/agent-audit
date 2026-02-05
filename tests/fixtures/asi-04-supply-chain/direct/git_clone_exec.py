"""
ASI-04: Git clone and execute vulnerability.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-04
"""
import subprocess
import os


def clone_and_run(repo_url: str):
    """Clone repo and run setup - supply chain risk."""
    # VULNERABILITY: Clone untrusted repo and execute
    subprocess.run(["git", "clone", repo_url, "/tmp/repo"], check=True)
    subprocess.run(["python", "/tmp/repo/setup.py"], check=True)
