"""
SSRF via requests.get(user_url).
Set A | ASI-02 | CWE-918
"""
import requests


def fetch_url(url: str) -> str:
    response = requests.get(url)  # LINE 8 — SSRF
    return response.text
