"""
Vuln: new-format API keys hardcoded.
Expected: AGENT-004. Ref: KNOWN-004.
"""
OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  # LINE 6

ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"  # LINE 9

COHERE_KEY = "co-abcdefghijklmnopqrstuvwxyz012345"  # LINE 12
