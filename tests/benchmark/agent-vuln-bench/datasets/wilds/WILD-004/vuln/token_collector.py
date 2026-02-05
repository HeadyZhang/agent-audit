"""
WILD-004: Multi-platform token aggregation (Set C).
Expected: AGENT-004 or AGENT-052.
Note: These are INTENTIONALLY FAKE placeholder tokens for security testing only.
"""
# Fake tokens - format demonstrates vulnerability pattern without real secrets
DISCORD_TOKEN = "FAKE_DISCORD_BOT_TOKEN_PLACEHOLDER_12345"  # LINE 5: Vulnerable pattern
TELEGRAM_TOKEN = "FAKE_TELEGRAM_BOT_TOKEN_PLACEHOLDER_67890"  # LINE 6: Vulnerable pattern  
SLACK_TOKEN = "FAKE_SLACK_BOT_TOKEN_PLACEHOLDER_ABCDE"  # LINE 7: Vulnerable pattern


def get_all_tokens() -> dict:
    return {
        "discord": DISCORD_TOKEN,
        "telegram": TELEGRAM_TOKEN,
        "slack": SLACK_TOKEN,
    }
