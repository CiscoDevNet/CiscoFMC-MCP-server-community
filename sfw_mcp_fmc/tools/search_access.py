# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from ..config import FMCSettings
from ..errors import InvalidIndicatorError
from ..fmc.client import FMCClient
from ..logging_conf import configure_logging
from ..match.indicator import QueryKind, classify_indicator, collect_matching_literals
from .find_rules import build_object_index, serialize_network_object

logger = configure_logging("sfw-mcp-fmc")

NETWORK_INDICATOR_TYPES = {"auto", "ip", "subnet", "fqdn"}
IDENTITY_INDICATOR_TYPES = {"sgt", "realm_user", "realm_group"}
VALID_INDICATOR_TYPES = NETWORK_INDICATOR_TYPES | IDENTITY_INDICATOR_TYPES


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _match_identity_objects(
    block: Optional[Dict[str, Any]],
    indicator_norm: str,
    *,
    allowed_types: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    if not block or not indicator_norm:
        return []

    matches: List[Dict[str, Any]] = []
    for ref in block.get("objects") or []:
        if not isinstance(ref, dict):
            continue
        ref_type = _norm(ref.get("type"))
        if allowed_types and ref_type not in allowed_types:
            continue

        if indicator_norm in {_norm(ref.get("name")), _norm(ref.get("id"))}:
            matches.append(
                {
                    "id": ref.get("id"),
                    "name": ref.get("name"),
                    "type": ref.get("type"),
                    "realm": ref.get("realm"),
                }
            )

    return matches


async def search_access_rules_impl(
    *,
    indicator: str,
    indicator_type: Literal["auto", "ip", "subnet", "fqdn", "sgt", "realm_user", "realm_group"] = "auto",
    rule_set: Literal["access", "prefilter", "both"] = "access",
    scope: Literal["policy", "fmc"] = "fmc",
    policy_name: Optional[str] = None,
    policy_id: Optional[str] = None,
    policy_name_contains: Optional[str] = None,
    max_policies: int = 0,
    # Rule-level prefilters
    rule_section: Optional[str] = None,
    rule_action: Optional[str] = None,
    enabled_only: Optional[bool] = None,
    rule_name_contains: Optional[str] = None,
    max_results: int = 100,
    domain_uuid: Optional[str] = None,
    client: Optional[FMCClient] = None,
) -> Dict[str, Any]:
    if max_results < 1:
        max_results = 1
    elif max_results > 500:
        max_results = 500

    if max_policies < 0:
        max_policies = 0
    elif max_policies > 1000:
        max_policies = 1000

    if scope not in ("policy", "fmc"):
        return {"error": {"category": "VALIDATION", "message": f"Unsupported scope '{scope}'."}}

    if rule_set not in ("access", "prefilter", "both"):
        return {"error": {"category": "VALIDATION", "message": f"Unsupported rule_set '{rule_set}'."}}

    if scope == "policy" and not (policy_name or policy_id):
        return {
            "error": {
                "category": "VALIDATION",
                "message": "scope='policy' requires policy_name or policy_id.",
            }
        }

    if client is None:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid
        client = FMCClient(settings)
    else:
        settings = client.settings

    if indicator_type not in VALID_INDICATOR_TYPES:
        return {
            "error": {
                "category": "VALIDATION",
                "message": f"Unsupported indicator_type '{indicator_type}'.",
            }
        }

    network_indicator = indicator_type in NETWORK_INDICATOR_TYPES
    identity_indicator_norm: Optional[str] = None

    if network_indicator:
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
    else:
        kind = None
        value = None
        identity_indicator_norm = _norm(indicator)
        if not identity_indicator_norm:
            return {
                "error": {
                    "category": "INVALID_INDICATOR",
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "message": "Indicator cannot be empty for this indicator_type.",
                }
            }
        effective_indicator_type = indicator_type

    # ---- Policy sources based on rule_set ----
    policy_sources: List[Tuple[str, List[Dict[str, Any]]]] = []
    if rule_set in ("access", "both"):
        aps = await client.list_access_policies(expanded=True)
        policy_sources.append(("AccessPolicy", aps))
    if rule_set in ("prefilter", "both"):
        pps = await client.list_prefilter_policies(expanded=True)
        policy_sources.append(("PrefilterPolicy", pps))

    all_policies: List[Dict[str, Any]] = []
    for ptype, plist in policy_sources:
        for p in plist:
            x = dict(p)
            x["_policyType"] = ptype
            all_policies.append(x)

    if not all_policies:
        return {"error": {"category": "FMC_CLIENT", "message": "No policies found on FMC for selected rule_set."}}

    # ---- Policy prefiltering ----
    filtered_policies: List[Dict[str, Any]] = all_policies

    if policy_id:
        # FMC IDs can appear with different casing depending on which endpoint returned them
        # (policy assignments sometimes return lowercase ids).
        # Treat policy_id matching as case-insensitive.
        pid = policy_id.strip().lower()
        filtered_policies = [
            p
            for p in filtered_policies
            if (p.get("id") or "").strip().lower() == pid
        ]
        if not filtered_policies:
            return {
                "error": {
                    "category": "NOT_FOUND",
                    "message": f"No policy with id '{policy_id}' was found for rule_set='{rule_set}'.",
                }
            }

    elif policy_name:
        name_norm = _norm(policy_name)
        filtered_policies = [p for p in filtered_policies if _norm(p.get("name")) == name_norm]
        if not filtered_policies:
            return {
                "error": {
                    "category": "RESOLUTION",
                    "message": f"No policy named '{policy_name}' was found for rule_set='{rule_set}'.",
                    "available_policies": sorted(
                        (p.get("name") or "").strip() for p in all_policies if p.get("name")
                    ),
                }
            }
    elif policy_name_contains:
        needle = _norm(policy_name_contains)
        filtered_policies = [p for p in filtered_policies if needle in _norm(p.get("name"))]
        if not filtered_policies:
            return {
                "error": {
                    "category": "RESOLUTION",
                    "message": f"No policy name contains '{policy_name_contains}' for rule_set='{rule_set}'.",
                    "available_policies": sorted(
                        (p.get("name") or "").strip() for p in all_policies if p.get("name")
                    ),
                }
            }

    if max_policies > 0:
        filtered_policies = filtered_policies[:max_policies]

    # Build object index once (shared for access + prefilter rules) when indicator is network-based
    matching_objects: List[Any] = []
    matched_object_ids: Dict[str, Dict[str, Any]] = {}
    if network_indicator and kind is not None and value is not None:
        obj_index = await build_object_index(client)
        matching_objects = obj_index.match_objects(kind, value)
        matched_object_ids = {o.id: serialize_network_object(o) for o in matching_objects}

    # ---- Rule filtering helpers ----
    section_norm = _norm(rule_section)
    action_norm = _norm(rule_action)
    rule_name_needle = _norm(rule_name_contains)

    def rule_passes_prefilters(rule: Dict[str, Any], policy_type: str) -> bool:
        if enabled_only is not None:
            enabled = bool(rule.get("enabled", True))
            if enabled_only and not enabled:
                return False
            if (enabled_only is False) and enabled:
                return False

        if action_norm:
            action = _norm(rule.get("action"))
            if action != action_norm:
                return False

        if rule_name_needle:
            name = _norm(rule.get("name"))
            if rule_name_needle not in name:
                return False

        # section exists for AccessRules; PrefilterRules typically don't have metadata.section
        if section_norm:
            section = _norm(rule.get("metadata", {}).get("section"))
            if section != section_norm:
                return False

        return True

    matched_items: List[Dict[str, Any]] = []
    scanned_policies = 0
    truncated = False

    for pol in filtered_policies:
        policy_id_val = (pol.get("id") or "").strip()
        policy_name_val = pol.get("name")
        policy_type = pol.get("_policyType") or "Unknown"
        if not policy_id_val:
            continue

        scanned_policies += 1

        if policy_type == "AccessPolicy":
            rules = await client.list_access_rules(policy_id_val, expanded=True)
            rule_type_label = "AccessRule"
        else:
            rules = await client.list_prefilter_rules(policy_id_val, expanded=True)
            rule_type_label = "PrefilterRule"

        for rule in rules:
            if not rule_passes_prefilters(rule, policy_type):
                continue

            src_block = (rule.get("sourceNetworks") or {}).copy()
            dst_block = (rule.get("destinationNetworks") or {}).copy()

            src_lit_matches: List[Dict[str, Any]] = []
            dst_lit_matches: List[Dict[str, Any]] = []
            src_object_matches: List[Dict[str, Any]] = []
            dst_object_matches: List[Dict[str, Any]] = []

            if network_indicator and kind is not None and value is not None:
                src_lit_matches = collect_matching_literals(kind, value, src_block)
                dst_lit_matches = collect_matching_literals(kind, value, dst_block)

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

            source_sgt_matches: List[Dict[str, Any]] = []
            destination_sgt_matches: List[Dict[str, Any]] = []
            user_matches: List[Dict[str, Any]] = []

            if indicator_type == "sgt" and identity_indicator_norm:
                allowed = {"isesecuritygrouptag"}
                source_sgt_matches = _match_identity_objects(
                    rule.get("sourceSecurityGroupTags"), identity_indicator_norm, allowed_types=allowed
                )
                destination_sgt_matches = _match_identity_objects(
                    rule.get("destinationSecurityGroupTags"), identity_indicator_norm, allowed_types=allowed
                )
            elif indicator_type == "realm_user" and identity_indicator_norm:
                allowed = {"realmuser"}
                user_matches = _match_identity_objects(
                    rule.get("users"),
                    identity_indicator_norm,
                    allowed_types=allowed,
                )
            elif indicator_type == "realm_group" and identity_indicator_norm:
                allowed = {"realmusergroup"}
                user_matches = _match_identity_objects(
                    rule.get("users"),
                    identity_indicator_norm,
                    allowed_types=allowed,
                )

            if not (
                src_lit_matches
                or dst_lit_matches
                or src_object_matches
                or dst_object_matches
                or source_sgt_matches
                or destination_sgt_matches
                or user_matches
            ):
                continue

            rule_entry = {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "type": rule_type_label,
                "policy_type": policy_type,
                "action": rule.get("action"),
                "enabled": rule.get("enabled", True),
                "metadata": {
                    "ruleIndex": rule.get("metadata", {}).get("ruleIndex"),
                    "section": rule.get("metadata", {}).get("section"),
                },
                "source_literal_matches": src_lit_matches,
                "destination_literal_matches": dst_lit_matches,
                "source_object_matches": src_object_matches,
                "destination_object_matches": dst_object_matches,
                "source_security_group_tag_matches": source_sgt_matches,
                "destination_security_group_tag_matches": destination_sgt_matches,
                "user_matches": user_matches,
            }

            matched_items.append(
                {
                    "policy": {"id": policy_id_val, "name": policy_name_val, "type": policy_type},
                    "rule": rule_entry,
                }
            )

            if len(matched_items) >= max_results:
                truncated = True
                break

        if truncated:
            break

    resolved_domain = await client.ensure_domain_uuid()

    meta: Dict[str, Any] = {
        "fmc": {"base_url": settings.base_url, "domain_uuid": resolved_domain},
        "indicator": indicator,
        "indicator_type": effective_indicator_type,
        "rule_set": rule_set,
        "scope": scope,
        "policies_considered": len(filtered_policies),
        "policies_scanned": scanned_policies,
        "policies": [
            {"id": (p.get("id") or "").strip(), "name": p.get("name"), "type": p.get("_policyType")}
            for p in filtered_policies
            if p.get("id")
        ],
        "matched_rules_count": len(matched_items),
        "matched_object_count": len(matching_objects),
        "truncated": truncated,
        "prefilter": {
            "policy_id": policy_id,
            "policy_name": policy_name,
            "policy_name_contains": policy_name_contains,
            "max_policies": max_policies if max_policies > 0 else None,
            "rule_section": rule_section,
            "rule_action": rule_action,
            "enabled_only": enabled_only,
            "rule_name_contains": rule_name_contains,
        },
    }

    matched_objects_serialized: List[Dict[str, Any]] = []
    if matching_objects:
        matched_objects_serialized = [serialize_network_object(o) for o in matching_objects]

    return {"meta": meta, "items": matched_items, "matched_objects": matched_objects_serialized}
