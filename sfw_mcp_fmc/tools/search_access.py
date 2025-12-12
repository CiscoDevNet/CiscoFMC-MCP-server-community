from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from ..config import FMCSettings
from ..errors import InvalidIndicatorError
from ..fmc.client import FMCClient
from ..logging_conf import configure_logging
from ..match.indicator import QueryKind, classify_indicator, collect_matching_literals
from .find_rules import build_object_index, serialize_network_object

logger = configure_logging("sfw-mcp-fmc")


async def search_access_rules_impl(
    *,
    indicator: str,
    indicator_type: Literal["auto", "ip", "subnet", "fqdn"] = "auto",
    scope: Literal["policy", "fmc"] = "fmc",
    policy_name: Optional[str] = None,
    max_results: int = 100,
    domain_uuid: Optional[str] = None,
) -> Dict[str, Any]:
    if max_results < 1:
        max_results = 1
    elif max_results > 500:
        max_results = 500

    if scope not in ("policy", "fmc"):
        return {"error": {"category": "VALIDATION", "message": f"Unsupported scope '{scope}'."}}

    if scope == "policy" and not policy_name:
        return {"error": {"category": "VALIDATION", "message": "scope='policy' requires policy_name."}}

    settings = FMCSettings.from_env()
    if domain_uuid:
        settings.domain_uuid = domain_uuid

    client = FMCClient(settings)

    try:
        kind, value = classify_indicator(indicator, indicator_type)
    except InvalidIndicatorError as e:
        return {
            "error": {
                "category": "INVALID_INDICATOR",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "message": str(e),
            }
        }

    effective_indicator_type = (
        "ip" if kind == QueryKind.IP else "subnet" if kind == QueryKind.NETWORK else "fqdn"
    )

    policies = await client.list_access_policies(expanded=True)
    if not policies:
        return {"error": {"category": "FMC_CLIENT", "message": "No Access Policies found on FMC."}}

    filtered_policies: List[Dict[str, Any]] = []
    if scope == "policy":
        norm = policy_name.strip().lower()  # type: ignore[union-attr]
        filtered_policies = [p for p in policies if (p.get("name") or "").strip().lower() == norm]
        if not filtered_policies:
            return {
                "error": {
                    "category": "RESOLUTION",
                    "message": f"No Access Policy named '{policy_name}' was found on this FMC/domain.",
                    "available_policies": sorted((p.get("name") or "").strip() for p in policies if p.get("name")),
                }
            }
    else:
        filtered_policies = policies

    # Build object index once
    obj_index = await build_object_index(client)
    matching_objects = obj_index.match_objects(kind, value)

    matched_object_ids: Dict[str, Dict[str, Any]] = {
        o.id: serialize_network_object(o) for o in matching_objects
    }

    matched_items: List[Dict[str, Any]] = []
    scanned_policies = 0
    truncated = False

    for pol in filtered_policies:
        policy_id = pol.get("id")
        policy_name_val = pol.get("name")
        if not policy_id:
            continue

        scanned_policies += 1
        rules = await client.list_access_rules(policy_id, expanded=True)

        for rule in rules:
            src_block = (rule.get("sourceNetworks") or {}).copy()
            dst_block = (rule.get("destinationNetworks") or {}).copy()

            src_lit_matches = collect_matching_literals(kind, value, src_block)
            dst_lit_matches = collect_matching_literals(kind, value, dst_block)

            src_object_matches: List[Dict[str, Any]] = []
            dst_object_matches: List[Dict[str, Any]] = []

            for ref in src_block.get("objects") or []:
                obj_id = ref.get("id")
                if obj_id and obj_id in matched_object_ids:
                    src_object_matches.append(
                        {
                            "id": obj_id,
                            "name": ref.get("name") or matched_object_ids[obj_id]["name"],
                            "type": ref.get("type") or matched_object_ids[obj_id]["type"],
                        }
                    )

            for ref in dst_block.get("objects") or []:
                obj_id = ref.get("id")
                if obj_id and obj_id in matched_object_ids:
                    dst_object_matches.append(
                        {
                            "id": obj_id,
                            "name": ref.get("name") or matched_object_ids[obj_id]["name"],
                            "type": ref.get("type") or matched_object_ids[obj_id]["type"],
                        }
                    )

            if not (src_lit_matches or dst_lit_matches or src_object_matches or dst_object_matches):
                continue

            rule_entry = {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "section": rule.get("metadata", {}).get("section"),
                "action": rule.get("action"),
                "enabled": rule.get("enabled", True),
                "hit_count": rule.get("metadata", {}).get("ruleHitCount"),
                "metadata": {
                    "ruleIndex": rule.get("metadata", {}).get("ruleIndex"),
                    "section": rule.get("metadata", {}).get("section"),
                },
                "source_literal_matches": src_lit_matches,
                "destination_literal_matches": dst_lit_matches,
                "source_object_matches": src_object_matches,
                "destination_object_matches": dst_object_matches,
            }

            matched_items.append({"policy": {"id": policy_id, "name": policy_name_val}, "rule": rule_entry})

            if len(matched_items) >= max_results:
                truncated = True
                break

        if len(matched_items) >= max_results:
            break

    resolved_domain = await client.ensure_domain_uuid()

    meta: Dict[str, Any] = {
        "indicator": indicator,
        "indicator_type": effective_indicator_type,
        "scope": scope,
        "fmc": {"base_url": settings.base_url, "domain_uuid": resolved_domain},
        "policies_scanned": scanned_policies,
        "matched_rules_count": len(matched_items),
        "matched_object_count": len(matching_objects),
        "truncated": truncated,
    }
    if scope == "policy":
        meta["policy_filter"] = policy_name

    return {"meta": meta, "items": matched_items}
