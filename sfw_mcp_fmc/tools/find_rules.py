from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..errors import InvalidIndicatorError
from ..fmc.client import FMCClient
from ..logging_conf import configure_logging
from ..match.indicator import classify_indicator, collect_matching_literals
from ..match.network_index import NetworkObject, NetworkObjectIndex

logger = configure_logging("sfw-mcp-fmc")


def _dynamic_page_limit_from_env() -> int:
    raw = os.getenv("FMC_DYNAMICOBJECT_MAX_PAGES", "5")
    try:
        return max(1, int(raw))
    except ValueError:
        return 5


def serialize_network_object(obj: NetworkObject) -> Dict[str, Any]:
    return {
        "id": obj.id,
        "name": obj.name,
        "type": obj.type,
        "fqdns": list(obj.fqdns),
        "members": list(obj.member_ids),
        "has_intervals": bool(obj.intervals),
    }


async def build_object_index(client: FMCClient) -> NetworkObjectIndex:
    idx = NetworkObjectIndex()

    hosts = await client.list_host_objects()
    for o in hosts:
        idx.add_host(o)

    networks = await client.list_network_objects()
    for o in networks:
        idx.add_network(o)

    ranges = await client.list_range_objects()
    for o in ranges:
        idx.add_range(o)

    fqdns = await client.list_fqdn_objects()
    for o in fqdns:
        idx.add_fqdn(o)

    groups = await client.list_network_groups()
    for o in groups:
        idx.add_network_group(o)

    dynamics = await client.list_dynamic_objects(hard_page_limit=_dynamic_page_limit_from_env())
    for o in dynamics:
        idx.add_dynamic_object(o)

    logger.info(
        "Indexed %s objects (hosts=%s networks=%s ranges=%s fqdns=%s groups=%s dynamics=%s)",
        len(idx.by_id),
        len(hosts),
        len(networks),
        len(ranges),
        len(fqdns),
        len(groups),
        len(dynamics),
    )
    return idx


async def search_rules_in_policy(
    *,
    client: FMCClient,
    query: str,
    access_policy_id: str,
) -> Dict[str, Any]:
    resolved_domain = await client.ensure_domain_uuid()

    try:
        query_kind, query_value = classify_indicator(query, "auto")
    except InvalidIndicatorError as e:
        raise InvalidIndicatorError(f"Invalid query indicator: {e}") from e

    obj_index = await build_object_index(client)
    matching_objects = obj_index.match_objects(query_kind, query_value)

    matched_object_ids: Dict[str, Dict[str, Any]] = {
        o.id: serialize_network_object(o) for o in matching_objects
    }

    rules = await client.list_access_rules(access_policy_id, expanded=True)

    matched_rules: List[Dict[str, Any]] = []

    for rule in rules:
        src_block = (rule.get("sourceNetworks") or {}).copy()
        dst_block = (rule.get("destinationNetworks") or {}).copy()

        src_lit_matches = collect_matching_literals(query_kind, query_value, src_block)
        dst_lit_matches = collect_matching_literals(query_kind, query_value, dst_block)

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

        matched_rules.append(
            {
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
        )

    return {
        "fmc_base_url": client.settings.base_url,
        "domain_uuid": resolved_domain,
        "access_policy_id": access_policy_id,
        "query": query,
        "query_kind": query_kind,
        "matched_object_count": len(matching_objects),
        "object_match_summary": [serialize_network_object(o) for o in matching_objects],
        "matched_rule_count": len(matched_rules),
        "matched_rules": matched_rules,
    }
