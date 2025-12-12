from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .logging_conf import configure_logging

logger = configure_logging("sfw-mcp-fmc")


def _to_bool(value: str) -> bool:
    v = value.strip().lower()
    return v in {"1", "true", "yes", "y"}


@dataclass
class FMCSettings:
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: float = 30.0
    domain_uuid: Optional[str] = None

    @classmethod
    def from_env(cls) -> "FMCSettings":
        base_url = os.getenv("FMC_BASE_URL")
        username = os.getenv("FMC_USERNAME")
        password = os.getenv("FMC_PASSWORD")

        if not base_url or not username or not password:
            raise ValueError("FMC_BASE_URL, FMC_USERNAME, and FMC_PASSWORD must be set")

        verify_ssl = _to_bool(os.getenv("FMC_VERIFY_SSL", "false"))

        timeout_raw = os.getenv("FMC_TIMEOUT", "30").strip()
        try:
            timeout = float(timeout_raw)
        except ValueError:
            logger.warning("Invalid FMC_TIMEOUT=%s, falling back to 30", timeout_raw)
            timeout = 30.0

        domain_uuid = os.getenv("FMC_DOMAIN_UUID")

        return cls(
            base_url=base_url.rstrip("/"),
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            domain_uuid=domain_uuid,
        )
