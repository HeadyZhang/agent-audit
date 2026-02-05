"""
ASI-08: Retry without backoff - cascading failure risk.
Rule: AGENT-021
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-08
"""
import time


def retry_forever(func):
    """Retry function forever - no circuit breaker."""
    # VULNERABILITY: Missing circuit breaker
    while True:
        try:
            return func()
        except Exception:
            time.sleep(0.1)  # No backoff, no limit
