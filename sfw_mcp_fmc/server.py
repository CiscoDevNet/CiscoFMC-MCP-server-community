from __future__ import annotations

import json
import os
from typing import Any, Dict, Literal, Optional

from fastmcp import FastMCP

from .config import FMCSettings
from .errors import InvalidIndicatorError
from .fmc.client import FMCClient
from .logging_conf import configure_logging
from .tools.find_rules import search_rules_in_policy
from .tools.search_access import search_access_rules_impl
from .tools.target_resolver import resolve_target_policies

logger = configure_logging("sfw-mcp-fmc")

mcp = FastMCP("cisco-secure-firewall-fmc")


@mcp.tool()
async def find_rules_by_ip_or_fqdn(
    query: str,
    access_policy_id: str,
    domain_uuid: Optional[str] = None,
) -> str:
    try:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid

        client = FMCClient(settings)
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
    rule_set: Literal["access", "prefilter", "both"] = "access",
    domain_uuid: Optional[str] = None,
) -> str:
    try:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid

        # We still instantiate a client to resolve target assignments.
        client = FMCClient(settings)
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
                    indicator_type="auto",
                    rule_set="access",
                    scope="policy",
                    policy_id=ap["id"],
                    max_policies=1,
                    max_results=200,
                    domain_uuid=domain_uuid,
                )
            else:
                out["access_result"] = {"error": {"category": "RESOLUTION", "message": "No Access Policy assigned to this target."}}

        if rule_set in ("prefilter", "both"):
            pp = resolved.get("prefilter_policy") or {}
            if pp.get("id"):
                out["prefilter_result"] = await search_access_rules_impl(
                    indicator=query,
                    indicator_type="auto",
                    rule_set="prefilter",
                    scope="policy",
                    policy_id=pp["id"],
                    max_policies=1,
                    max_results=200,
                    domain_uuid=domain_uuid,
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
    indicator_type: Literal["auto", "ip", "subnet", "fqdn"] = "auto",
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
) -> Dict[str, Any]:
    try:
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
        )
    except Exception as exc:
        logger.exception("Unexpected error in search_access_rules")
        return {"error": {"category": "UNEXPECTED", "message": str(exc)}}


def main() -> None:
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
