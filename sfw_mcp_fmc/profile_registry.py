# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .config import FMCSettings
from .logging_conf import configure_logging

logger = configure_logging("sfw-mcp-fmc")


@dataclass
class FMCProfile:
    profile_id: str
    display_name: str
    aliases: List[str]
    settings: FMCSettings
    log_level: Optional[str] = None
    httpx_log_level: Optional[str] = None
    httpx_trace: Optional[str] = None


class FMCProfileRegistry:
    def __init__(self, profiles: Iterable[FMCProfile], default_profile_id: Optional[str] = None) -> None:
        entries = {p.profile_id: p for p in profiles}
        if not entries:
            raise ValueError("No FMC profiles were loaded")

        if default_profile_id and default_profile_id not in entries:
            logger.warning(
                "Requested default profile %s not found among %s; using first profile",
                default_profile_id,
                list(entries),
            )
            default_profile_id = None

        self._profiles: Dict[str, FMCProfile] = entries
        self._default_profile_id = default_profile_id or next(iter(entries.keys()))

    @property
    def default_profile_id(self) -> str:
        return self._default_profile_id

    def list_profiles(self) -> List[FMCProfile]:
        return list(self._profiles.values())

    def resolve(self, key: Optional[str]) -> FMCProfile:
        if not key:
            return self._profiles[self._default_profile_id]

        key_norm = key.strip().lower()
        if not key_norm:
            return self._profiles[self._default_profile_id]

        # direct id match
        for profile in self._profiles.values():
            if profile.profile_id.lower() == key_norm:
                return profile
            for alias in profile.aliases:
                if alias.lower() == key_norm:
                    return profile

        raise ValueError(f"Unknown FMC profile: {key}")

    @classmethod
    def from_env(cls) -> "FMCProfileRegistry":
        directory = os.getenv("FMC_PROFILES_DIR")
        if not directory:
            raise ValueError("FMC_PROFILES_DIR must be set to use multiple FMC profiles")

        default_profile = os.getenv("FMC_PROFILE_DEFAULT")
        return cls.from_directory(directory, default_profile_id=default_profile)

    @classmethod
    def from_directory(cls, directory: str, *, default_profile_id: Optional[str] = None) -> "FMCProfileRegistry":
        base_path = Path(directory)
        if not base_path.exists() or not base_path.is_dir():
            raise ValueError(f"FMC profiles directory does not exist: {directory}")

        profiles: List[FMCProfile] = []
        for env_file in sorted(base_path.glob("*.env")):
            data = _load_env_file(env_file)
            try:
                settings = FMCSettings.from_mapping(data)
            except ValueError as exc:
                logger.warning("Skipping profile file %s: %s", env_file, exc)
                continue

            profile_id = data.get("FMC_PROFILE_ID") or env_file.stem
            display_name = data.get("FMC_PROFILE_DISPLAY_NAME") or profile_id.replace("-", " ").title()
            aliases = _parse_aliases(data.get("FMC_PROFILE_ALIASES"))
            log_level = _clean_env_value(data.get("LOG_LEVEL"))
            httpx_log_level = _clean_env_value(data.get("HTTPX_LOG_LEVEL"))
            httpx_trace = _clean_env_value(data.get("HTTPX_TRACE"))

            profiles.append(
                FMCProfile(
                    profile_id=profile_id,
                    display_name=display_name,
                    aliases=aliases,
                    settings=settings,
                    log_level=log_level,
                    httpx_log_level=httpx_log_level,
                    httpx_trace=httpx_trace,
                )
            )

        if not profiles:
            raise ValueError(f"No valid FMC profiles were discovered in {directory}")

        return cls(profiles, default_profile_id=default_profile_id)


def _load_env_file(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _parse_aliases(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [alias.strip() for alias in raw.split(",") if alias.strip()]


def _clean_env_value(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    value = raw.strip()
    return value or None
