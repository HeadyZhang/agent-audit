"""
BENIGN: URL fetch with allowlist validation.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import requests
from urllib.parse import urlparse
from langchain_core.tools import tool


ALLOWED_DOMAINS = {"api.example.com", "data.example.org"}


@tool
def safe_fetch(url: str) -> str:
    """Fetch from allowed domains only."""
    try:
        # SAFE: URL allowlist validation
        parsed = urlparse(url)
        if parsed.netloc not in ALLOWED_DOMAINS:
            return f"Error: Domain not allowed: {parsed.netloc}"

        # SAFE: Only after domain validation
        response = requests.get(url, timeout=30)
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"
