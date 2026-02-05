"""
Vuln: access to system credential store.
Expected: AGENT-046 (not AGENT-004).
"""
import subprocess


def read_keychain_password(service: str) -> str:
    result = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-w"],  # LINE 8
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
