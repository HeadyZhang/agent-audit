"""
ASI-08: Tool without error handling.
Rule: AGENT-022
Expected: TRUE POSITIVE at line 13
"""
from langchain_core.tools import tool
import requests


@tool
def fetch_api_data(url: str) -> str:
    """Fetch data from API without error handling."""
    # VULNERABILITY: No try/except for external call
    response = requests.get(url)
    return response.json()
