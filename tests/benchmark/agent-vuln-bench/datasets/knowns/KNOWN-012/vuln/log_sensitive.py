"""
Logging sensitive data.
Set C | ASI-09 | CWE-532
"""
import logging

logger = logging.getLogger(__name__)


def login(user: str, token: str) -> None:
    logger.info(f"User token: {token}")  # LINE 9 — sensitive in log
    logger.info(f"User {user} authenticated")
