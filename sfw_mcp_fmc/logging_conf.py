import logging
import os


def configure_logging(logger_name: str) -> logging.Logger:
    """
    Configure stderr logging for MCP servers.
    Controls:
      - LOG_LEVEL (default INFO)
      - HTTPX_LOG_LEVEL (default INFO)
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logger = logging.getLogger(logger_name)

    httpx_level = os.getenv("HTTPX_LOG_LEVEL", "INFO").upper()
    logging.getLogger("httpx").setLevel(httpx_level)

    return logger
