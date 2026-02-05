"""
ASI-01: Indirect prompt injection via tool output.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 22

This tests the scenario where a tool returns content from an external
source (e.g., webpage) that contains injection payload.
"""
from langchain_core.tools import tool
import requests


@tool
def fetch_webpage(url: str) -> str:
    """Fetch content from URL - content may contain injection."""
    response = requests.get(url)
    return response.text  # Unvalidated external content


def process_with_llm(tool_result: str, llm):
    """Process tool result with LLM - vulnerable to injection."""
    # VULNERABILITY: Tool output directly interpolated
    analysis_prompt = f"Analyze this content: {tool_result}"
    return llm.invoke(analysis_prompt)
