"""
Agent Configuration with Hardcoded API Keys
Pattern: Common mistake in AI agent projects

This pattern is observed in hundreds of GitHub repositories where
developers hardcode API keys directly in source code.

VULNERABILITY: Hardcoded credentials expose API keys to anyone
with access to the source code, leading to credential theft and
financial loss through API abuse.
"""
from __future__ import annotations

import os
from typing import Optional

# VULNERABILITY: Hardcoded OpenAI API key
# Real pattern: developers copy-paste keys during development
# and forget to remove them before committing
OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdefghijk"

# VULNERABILITY: Multiple hardcoded API keys
ANTHROPIC_API_KEY = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
COHERE_API_KEY = "co-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


class AgentConfig:
    """Configuration for the AI agent."""

    def __init__(
        self,
        model: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        # VULNERABILITY: Using hardcoded key as fallback
        self.api_key = os.getenv("OPENAI_API_KEY", OPENAI_API_KEY)

        # VULNERABILITY: Directly using hardcoded key
        self.anthropic_key = ANTHROPIC_API_KEY

    def get_openai_client(self):
        """Create OpenAI client with hardcoded key."""
        # Simulated import to avoid real dependency
        # from openai import OpenAI
        # return OpenAI(api_key=self.api_key)
        pass

    def get_headers(self) -> dict:
        """Get API headers with hardcoded key."""
        return {
            "Authorization": f"Bearer {OPENAI_API_KEY}",  # VULN: Direct use
            "Content-Type": "application/json",
        }


# VULNERABILITY: Keys in module-level initialization
def create_default_client():
    """Create a default client with hardcoded credentials."""
    # This pattern is extremely common in tutorials and quick-start code
    # from openai import OpenAI
    # client = OpenAI(api_key="sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdefghijk")
    # return client
    pass


# VULNERABILITY: Connection strings with embedded credentials
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.example.com:5432/agents"
REDIS_URL = "redis://:password123@redis.example.com:6379/0"


# Example of how this is typically used
if __name__ == "__main__":
    config = AgentConfig()
    print(f"Using API key: {config.api_key[:10]}...")  # Still leaks prefix
