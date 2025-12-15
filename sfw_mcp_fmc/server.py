from __future__ import annotations

import json
import os
from dataclasses import replace
from typing import Any, Dict, Literal, Optional

from fastmcp import FastMCP

from .config import FMCSettings
from .errors import InvalidIndicatorError
from .fmc.client import FMCClient
from .logging_conf import configure_logging
from .profile_registry import FMCProfileRegistry
from .tools.find_rules import search_rules_in_policy
from .tools.search_access import search_access_rules_impl
from .tools.target_resolver import resolve_target_policies

logger = configure_logging("sfw-mcp-fmc")

SERVER_INSTRUCTIONS = (
    "Use list_fmc_profiles first to discover available FMC instances (env mode exposes a single "
    "default profile). Pass the chosen profile id/alias as fmc_profile or omit it to let the server "
    "use its default. All tools are read-only:\n"
    "• find_rules_by_ip_or_fqdn searches one access policy by id.\n"
    "• find_rules_for_target resolves an FTD/HA/cluster target to its assigned access/prefilter "
    "policies before searching them.\n"
    "• search_access_rules performs FMC-wide or policy-scoped searches across access/prefilter policies "
    "and supports network + identity indicators with optional rule filters.\n"
    "Credentials come from env vars or profile files; only the FMC REST API is called."
)

mcp = FastMCP("cisco-secure-firewall-fmc", instructions=SERVER_INSTRUCTIONS)
registry: Optional[FMCProfileRegistry] = None
_client_cache: Dict[str, FMCClient] = {}


def create_client(profile_key: Optional[str], *, domain_uuid_override: Optional[str] = None) -> FMCClient:
    if registry:
        profile = registry.resolve(profile_key)
        settings = profile.settings
        if domain_uuid_override:
            override = replace(settings, domain_uuid=domain_uuid_override)
            return FMCClient(override)

        cache_key = profile.profile_id
        if cache_key not in _client_cache:
            _client_cache[cache_key] = FMCClient(settings)
        return _client_cache[cache_key]

    cache_key = "__default__"
    if domain_uuid_override:
        settings = FMCSettings.from_env()
        override = replace(settings, domain_uuid=domain_uuid_override)
        return FMCClient(override)

    if cache_key not in _client_cache:
        settings = FMCSettings.from_env()
        _client_cache[cache_key] = FMCClient(settings)
    return _client_cache[cache_key]


@mcp.tool()
async def list_fmc_profiles() -> Dict[str, Any]:
    """Describe available FMC profiles from env mode (single) or profile registry (multi)."""
    if not registry:
        settings = FMCSettings.from_env()
        return {
            "mode": "single",
            "profiles": [
                {
                    "id": "default",
                    "display_name": "Default FMC (env)",
                    "aliases": [],
                    "base_url": settings.base_url,
                    "verify_ssl": settings.verify_ssl,
                }
            ],
        }

    profiles = []
    for profile in registry.list_profiles():
        profiles.append(
            {
                "id": profile.profile_id,
                "display_name": profile.display_name,
                "aliases": profile.aliases,
                "base_url": profile.settings.base_url,
                "verify_ssl": profile.settings.verify_ssl,
                "default": profile.profile_id == registry.default_profile_id,
            }
        )

    return {"mode": "multi", "profiles": profiles, "default_profile": registry.default_profile_id}


@mcp.tool()
async def find_rules_by_ip_or_fqdn(
    query: str,
    access_policy_id: str,
    domain_uuid: Optional[str] = None,
    fmc_profile: Optional[str] = None,
) -> str:
    """Search a specific access policy for rules referencing an IP/CIDR/FQDN indicator."""
    try:
        client = create_client(fmc_profile, domain_uuid_override=domain_uuid)
        result = await search_rules_in_policy(
            client=client, query=query, access_policy_id=access_policy_id
        )
        return json.dumps(result, indent=2)

    except InvalidIndicatorError as e:
        return json.dumps({"error": {"category": "INVALID_INDICATOR", "message": str(e)}}, indent=2)
    except Exception as exc:
        logger.exception("Unexpected error in find_rules_by_ip_or_fqdn")
        return json.dumps({"error": {"category": "UNEXPECTED", "message": str(exc)}}, indent=2)


@mcp.tool()
async def find_rules_for_target(
    query: str,
    target: str,
    indicator_type: Literal["auto", "ip", "subnet", "fqdn", "sgt", "realm_user", "realm_group"] = "auto",
    rule_set: Literal["access", "prefilter", "both"] = "access",
    domain_uuid: Optional[str] = None,
    fmc_profile: Optional[str] = None,
) -> str:
    """Resolve an FTD/HA/cluster target to its policies and search them for the indicator."""
    try:
        client = create_client(fmc_profile, domain_uuid_override=domain_uuid)
        await client.ensure_domain_uuid()

        resolved, note = await resolve_target_policies(client, target)
        resolved = resolved or {}

        out: Dict[str, Any] = {
            "target": target,
            "query": query,
            "rule_set": rule_set,
            "resolved_target": resolved,
            "resolution_note": note,
        }

        # Delegate searching to the proven engine (supports access/prefilter/both)
        if rule_set in ("access", "both"):
            ap = resolved.get("access_policy") or {}
            if ap.get("id"):
                out["access_result"] = await search_access_rules_impl(
                    indicator=query,
                    indicator_type=indicator_type,
                    rule_set="access",
                    scope="policy",
                    policy_id=ap["id"],
                    max_policies=1,
                    max_results=200,
                    domain_uuid=domain_uuid,
                    client=client,
                )
            else:
                out["access_result"] = {"error": {"category": "RESOLUTION", "message": "No Access Policy assigned to this target."}}

        if rule_set in ("prefilter", "both"):
            pp = resolved.get("prefilter_policy") or {}
            if pp.get("id"):
                out["prefilter_result"] = await search_access_rules_impl(
                    indicator=query,
                    indicator_type=indicator_type,
                    rule_set="prefilter",
                    scope="policy",
                    policy_id=pp["id"],
                    max_policies=1,
                    max_results=200,
                    domain_uuid=domain_uuid,
                    client=client,
                )
            else:
                out["prefilter_result"] = {"error": {"category": "RESOLUTION", "message": "No Prefilter Policy assigned to this target."}}

        return json.dumps(out, indent=2)

    except InvalidIndicatorError as e:
        return json.dumps({"error": {"category": "INVALID_INDICATOR", "message": str(e)}}, indent=2)
    except ValueError as e:
        return json.dumps({"error": {"category": "RESOLUTION", "message": str(e)}}, indent=2)
    except Exception as exc:
        logger.exception("Unexpected error in find_rules_for_target")
        return json.dumps({"error": {"category": "UNEXPECTED", "message": str(exc)}}, indent=2)


@mcp.tool()
async def search_access_rules(
    indicator: str,
    indicator_type: Literal["auto", "ip", "subnet", "fqdn", "sgt", "realm_user", "realm_group"] = "auto",
    rule_set: Literal["access", "prefilter", "both"] = "access",
    scope: Literal["policy", "fmc"] = "fmc",
    policy_name: Optional[str] = None,
    policy_id: Optional[str] = None,
    policy_name_contains: Optional[str] = None,
    max_policies: int = 0,
    rule_section: Optional[str] = None,
    rule_action: Optional[str] = None,
    enabled_only: Optional[bool] = None,
    rule_name_contains: Optional[str] = None,
    max_results: int = 100,
    domain_uuid: Optional[str] = None,
    fmc_profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Run FMC-wide or policy-scoped rule searches with network/identity indicators and filters."""
    try:
        client = create_client(fmc_profile, domain_uuid_override=domain_uuid)
        return await search_access_rules_impl(
            indicator=indicator,
            indicator_type=indicator_type,
            rule_set=rule_set,
            scope=scope,
            policy_name=policy_name,
            policy_id=policy_id,
            policy_name_contains=policy_name_contains,
            max_policies=max_policies,
            rule_section=rule_section,
            rule_action=rule_action,
            enabled_only=enabled_only,
            rule_name_contains=rule_name_contains,
            max_results=max_results,
            domain_uuid=domain_uuid,
            client=client,
        )
    except Exception as exc:
        logger.exception("Unexpected error in search_access_rules")
        return {"error": {"category": "UNEXPECTED", "message": str(exc)}}


def main() -> None:
    global registry
    profiles_dir = os.getenv("FMC_PROFILES_DIR")
    if profiles_dir:
        try:
            registry = FMCProfileRegistry.from_env()
            logger.info(
                "Loaded FMC profiles: %s (default=%s)",
                [p.profile_id for p in registry.list_profiles()],
                registry.default_profile_id,
            )
        except Exception as exc:
            logger.error("Failed to load FMC profiles (dir=%s): %s", profiles_dir, exc)
            raise
    else:
        registry = None
        logger.info("FMC_PROFILES_DIR not set; running in single-FMC mode.")

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    if transport == "http":
        host = os.getenv("MCP_HOST", "0.0.0.0")
        port_raw = os.getenv("MCP_PORT", "8000")
        try:
            port = int(port_raw)
        except ValueError:
            port = 8000

        logger.info("Starting MCP server (transport=http) on %s:%s", host, port)
        mcp.run(transport="http", host=host, port=port)
    else:
        logger.info("Starting MCP server (transport=stdio)")
        mcp.run(transport="stdio")
