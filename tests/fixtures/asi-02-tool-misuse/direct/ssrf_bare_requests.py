"""
Vuln: bare requests.get(user_url) without @tool context.
Expected: AGENT-037. Ref: WILD-002.
"""
import requests


def fetch_url(url: str) -> str:
    """Fetch content from any URL"""
    response = requests.get(url)  # LINE 9 — SSRF
    return response.text


def process_agent_action(action: dict):
    if action["type"] == "web_fetch":
        return fetch_url(action["url"])
