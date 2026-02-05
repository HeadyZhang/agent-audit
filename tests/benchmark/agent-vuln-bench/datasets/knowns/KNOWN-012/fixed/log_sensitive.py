"""Fixed: no sensitive data in logs."""
import logging

logger = logging.getLogger(__name__)


def login(user: str, token: str) -> None:
    logger.info("User authenticated")  # no token in log
    logger.debug("Auth completed for user")
