"""
WILD-004: Multi-platform token aggregation (Set C).
Expected: AGENT-004 via Generic Token pattern.
Note: These are INTENTIONALLY FAKE tokens for security testing only.
      They use pattern-matching formats to trigger detection.
"""
# Fake tokens using formats that match secret scanner patterns
# LINE 7: token = assignment pattern triggers Generic Token detection
discord_token = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA"
# LINE 11: token = assignment pattern triggers Generic Token detection
telegram_token = "ABC12345DEFGHIJKLMNOPQRSTUVWXYZabc67890de"
# LINE 11: Slack xoxb format triggers Slack Bot Token detection
slack_token = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"


def get_all_tokens() -> dict:
    return {
        "discord": discord_token,
        "telegram": telegram_token,
        "slack": slack_token,
    }
