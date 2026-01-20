# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

import logging
import os


def configure_logging(logger_name: str) -> logging.Logger:
    """
    Configure stderr logging for MCP servers.
    Controls:
      - LOG_LEVEL (default INFO)
      - HTTPX_LOG_LEVEL (default WARNING)
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        force=True,
    )
    logging.getLogger().setLevel(log_level)
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    # Keep noisy container/app libs at WARNING unless explicitly overridden.
    for noisy in ("asyncio", "uvicorn", "uvicorn.error", "uvicorn.access", "fastmcp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    httpx_level_raw = os.getenv("HTTPX_LOG_LEVEL")
    httpx_level = httpx_level_raw.upper() if httpx_level_raw else "WARNING"
    logging.getLogger("httpx").setLevel(httpx_level)
    logging.getLogger("httpcore").setLevel(httpx_level)

    return logger
