"""
ASI-02: Server-Side Request Forgery (SSRF) via unvalidated URL.
Rule: AGENT-026
Expected: TRUE POSITIVE at line 14
"""
import requests
from langchain_core.tools import tool


@tool
def fetch_url(url: str) -> str:
    """Fetch content from URL."""
    # VULNERABILITY: No URL validation - allows internal network access
    response = requests.get(url)
    return response.text
