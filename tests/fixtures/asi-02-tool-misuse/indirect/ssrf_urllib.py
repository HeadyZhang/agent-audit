"""
Vuln: urllib SSRF variant.
Expected: AGENT-037.
"""
from urllib.request import urlopen


def read_remote_config(config_url: str) -> str:
    with urlopen(config_url) as response:  # LINE 7 — SSRF
        return response.read().decode()
