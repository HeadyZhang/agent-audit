"""
ASI-07: Shared Redis without authentication.
Rule: AGENT-020
Expected: TRUE POSITIVE at line 13
owasp_id: ASI-07
"""
import redis


def get_agent_bus():
    """Connect to shared agent message bus - no auth."""
    # VULNERABILITY: Unauthenticated inter-agent channel
    r = redis.Redis(host="shared-redis", port=6379)
    return r
