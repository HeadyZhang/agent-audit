"""Fixed: URL allowlist."""
import requests

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


def fetch_url(url: str) -> str:
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("URL not in allowlist")
    response = requests.get(url)
    return response.text
