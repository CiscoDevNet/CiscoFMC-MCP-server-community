# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

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
        return cls._from_mapping(os.environ)

    @classmethod
    def from_mapping(cls, data: Mapping[str, str]) -> "FMCSettings":
        return cls._from_mapping(data)

    @classmethod
    def _from_mapping(cls, data: Mapping[str, str]) -> "FMCSettings":
        base_url = data.get("FMC_BASE_URL")
        username = data.get("FMC_USERNAME")
        password = data.get("FMC_PASSWORD")
        if not base_url or not username or not password:
            raise ValueError("FMC_BASE_URL, FMC_USERNAME, and FMC_PASSWORD must be set")

        verify_ssl = _to_bool(data.get("FMC_VERIFY_SSL", "false"))
        timeout_raw = str(data.get("FMC_TIMEOUT", "30")).strip()
        try:
            timeout = float(timeout_raw)
        except ValueError:
            logger.warning("Invalid FMC_TIMEOUT=%s, falling back to 30", timeout_raw)
            timeout = 30.0

        domain_uuid = data.get("FMC_DOMAIN_UUID")

        return cls(
            base_url=base_url.rstrip("/"),
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            domain_uuid=domain_uuid,
        )
