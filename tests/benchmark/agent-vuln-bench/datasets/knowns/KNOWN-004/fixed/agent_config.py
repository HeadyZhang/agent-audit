"""
Agent Configuration with Proper Secret Management
Pattern: Secure handling of API keys

FIXED: All secrets are loaded from environment variables.
No hardcoded credentials in source code.
"""
from __future__ import annotations

import os
from typing import Optional


class ConfigurationError(Exception):
    """Raised when required configuration is missing."""

    pass


def get_required_env(name: str) -> str:
    """Get a required environment variable or raise error.

    Args:
        name: Name of the environment variable.

    Returns:
        Value of the environment variable.

    Raises:
        ConfigurationError: If the variable is not set.
    """
    value = os.getenv(name)
    if not value:
        raise ConfigurationError(
            f"Required environment variable '{name}' is not set. "
            f"Please set it in your environment or .env file."
        )
    return value


class AgentConfig:
    """Configuration for the AI agent with secure secret handling."""

    def __init__(
        self,
        model: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        # FIXED: Load from environment, fail if not set
        self._api_key: Optional[str] = None
        self._anthropic_key: Optional[str] = None

    @property
    def api_key(self) -> str:
        """Get OpenAI API key from environment."""
        if self._api_key is None:
            self._api_key = get_required_env("OPENAI_API_KEY")
        return self._api_key

    @property
    def anthropic_key(self) -> str:
        """Get Anthropic API key from environment."""
        if self._anthropic_key is None:
            self._anthropic_key = get_required_env("ANTHROPIC_API_KEY")
        return self._anthropic_key

    def get_openai_client(self):
        """Create OpenAI client with environment key."""
        # from openai import OpenAI
        # return OpenAI(api_key=self.api_key)
        pass

    def get_headers(self) -> dict:
        """Get API headers with environment key."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


def create_default_client():
    """Create a default client with environment credentials."""
    # FIXED: Use environment variable
    api_key = get_required_env("OPENAI_API_KEY")
    # from openai import OpenAI
    # return OpenAI(api_key=api_key)
    pass


# FIXED: Database URLs from environment
def get_database_url() -> str:
    """Get database URL from environment."""
    return get_required_env("DATABASE_URL")


def get_redis_url() -> str:
    """Get Redis URL from environment."""
    return get_required_env("REDIS_URL")


if __name__ == "__main__":
    # This will fail if environment variables are not set
    # which is the correct behavior
    try:
        config = AgentConfig()
        print(f"API key loaded: {config.api_key[:10]}***")
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        print("Please set required environment variables.")
