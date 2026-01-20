# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""
Target resolution helper.

Goal:
- Resolve a user-provided 'target' (device name/hostname OR HA pair OR cluster)
- Determine which Access Policy and Prefilter Policy are applied to that target

Important FMC behavior:
- Device records usually carry the Access Policy reference.
- Prefilter Policy is often referenced via AccessPolicy.prefilterPolicySetting
  (so we derive prefilter from the Access Policy when needed).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from ..logging_conf import configure_logging

logger = configure_logging("sfw-mcp-fmc")


def _safe_lower(v: Any) -> str:
    return str(v or "").strip().lower()


def _normalize_id(v: Any) -> str:
    """Return a normalized id string for comparison (case-insensitive)."""
    return _safe_lower(v)


def _match_target_record(target_lc: str, rec: Dict[str, Any]) -> bool:
    """Exact (case-insensitive) match against common name/hostname keys."""
    if not isinstance(rec, dict):
        return False

    # Common keys across device/ha/cluster objects
    if _safe_lower(rec.get("name")) == target_lc:
        return True

    # Device hostnames can be hostName/hostname/host_name depending on endpoint/version
    if _safe_lower(rec.get("hostName")) == target_lc:
        return True
    if _safe_lower(rec.get("hostname")) == target_lc:
        return True
    if _safe_lower(rec.get("host_name")) == target_lc:
        return True

    return False


def _contains_target_record(target_lc: str, rec: Dict[str, Any]) -> bool:
    """Fuzzy match: target is substring of name/hostname fields."""
    if not isinstance(rec, dict):
        return False

    cands = [
        rec.get("name"),
        rec.get("hostName"),
        rec.get("hostname"),
        rec.get("host_name"),
    ]
    return any(target_lc in _safe_lower(c) for c in cands if c)


def _extract_policies_from_resolved_target(raw: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Extract AccessPolicy and PrefilterPolicy references if they exist directly
    on the resolved object (device/ha/cluster/assignment payload).
    """
    access_pol = None
    prefilter_pol = None

    # Common direct keys on device records
    for k in ("accessPolicy", "accessPolicySetting"):
        v = raw.get(k)
        if isinstance(v, dict) and v.get("id") and v.get("type") in ("AccessPolicy", "AccessPolicySetting"):
            access_pol = {"id": v.get("id"), "name": v.get("name"), "type": "AccessPolicy"}

    for k in ("prefilterPolicy", "prefilterPolicySetting"):
        v = raw.get(k)
        if not isinstance(v, dict):
            continue
        if v.get("type") in ("PrefilterPolicy", "PrefilterPolicySetting"):
            if v.get("id"):
                prefilter_pol = {"id": v.get("id"), "name": v.get("name"), "type": "PrefilterPolicy"}
        if not prefilter_pol and k == "prefilterPolicySetting":
            candidate = _prefilter_from_setting(v)
            if candidate:
                prefilter_pol = candidate

    # Sometimes nested under policySettings
    ps = raw.get("policySettings")
    if isinstance(ps, dict):
        ap = ps.get("accessPolicy")
        if isinstance(ap, dict) and ap.get("id"):
            access_pol = {"id": ap.get("id"), "name": ap.get("name"), "type": "AccessPolicy"}

        pp = ps.get("prefilterPolicy")
        if isinstance(pp, dict) and pp.get("id"):
            prefilter_pol = {"id": pp.get("id"), "name": pp.get("name"), "type": "PrefilterPolicy"}
        if not prefilter_pol and isinstance(ps.get("prefilterPolicySetting"), dict):
            candidate = _prefilter_from_setting(ps.get("prefilterPolicySetting"))
            if candidate:
                prefilter_pol = candidate

    return access_pol, prefilter_pol


def _prefilter_from_setting(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    FMC reps prefilter mapping inside prefilterPolicySetting with various shapes:
      - {"prefilterPolicy": {...}}
      - {"value": {"id": ..., "name": ...}}
      - direct {"id": ..., "name": ...}
    """
    if not isinstance(payload, dict):
        return None

    candidate: Optional[Dict[str, Any]] = None
    if isinstance(payload.get("prefilterPolicy"), dict):
        candidate = payload.get("prefilterPolicy")
    elif isinstance(payload.get("value"), dict):
        candidate = payload.get("value")
    elif payload.get("id"):
        candidate = payload

    if isinstance(candidate, dict) and candidate.get("id"):
        return {
            "id": candidate.get("id"),
            "name": candidate.get("name"),
            "type": "PrefilterPolicy",
        }
    return None


def _extract_member_device_ids(raw: Dict[str, Any]) -> List[str]:
    """
    Pull out device ids from HA/cluster objects in a best-effort way.
    FMC structures vary, so we try common patterns.
    """
    ids: List[str] = []

    # HA-like patterns
    for k in ("primary", "secondary", "primaryDevice", "secondaryDevice"):
        v = raw.get(k)
        if isinstance(v, dict) and v.get("id"):
            ids.append(v["id"])

    # Cluster-like patterns
    for k in ("members", "devices", "deviceRecords"):
        v = raw.get(k)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and item.get("id"):
                    ids.append(item["id"])
        elif isinstance(v, dict):
            # some APIs wrap list in {"items":[...]}
            items = v.get("items")
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("id"):
                        ids.append(item["id"])

    # Dedup
    out: List[str] = []
    for i in ids:
        if i and i not in out:
            out.append(i)
    return out


def _assignment_target_ids(payload: Dict[str, Any]) -> List[str]:
    targets = payload.get("targets") or []
    ids: List[str] = []
    for t in targets:
        tid = _normalize_id(t.get("id"))
        if tid:
            ids.append(tid)
    return ids


def _assignment_policy_type(payload: Dict[str, Any]) -> str:
    pol = payload.get("policy") or {}
    return (
        _safe_lower(pol.get("type"))
        or _safe_lower(pol.get("policyType"))
        or _safe_lower(payload.get("policyType"))
    )


def _assignment_policy_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    pol = payload.get("policy")
    return pol if isinstance(pol, dict) else {}


async def _fill_policies_from_assignments(
    client: Any,
    candidate_ids: Set[str],
    access_pol: Optional[Dict[str, Any]],
    prefilter_pol: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not candidate_ids:
        return access_pol, prefilter_pol

    try:
        assignments = await client.list_policy_assignments()
    except Exception as exc:
        # Assignments endpoint isn't critical; log and continue.
        logger.warning("resolve_target: failed to list policy assignments: %s", exc)
        return access_pol, prefilter_pol

    for assignment in assignments or []:
        target_ids = set(_assignment_target_ids(assignment))
        if not target_ids or not target_ids.intersection(candidate_ids):
            continue

        pol_payload = _assignment_policy_payload(assignment)
        pol_id = pol_payload.get("id")
        if not pol_id:
            continue
        pol_name = pol_payload.get("name")
        pol_type = _assignment_policy_type(assignment)

        if not access_pol and pol_type in {"accesspolicy", "accesscontrolpolicy"}:
            access_pol = {"id": pol_id, "name": pol_name, "type": "AccessPolicy"}
        elif not prefilter_pol and pol_type in {"prefilterpolicy"}:
            prefilter_pol = {"id": pol_id, "name": pol_name, "type": "PrefilterPolicy"}

        if access_pol and prefilter_pol:
            break

    return access_pol, prefilter_pol


async def _prefilter_from_access_listing(client: Any, policy_id: str) -> Optional[Dict[str, Any]]:
    pid = _normalize_id(policy_id)
    if not pid:
        return None
    try:
        policies = await client.list_access_policies(expanded=True)
    except Exception as exc:
        logger.warning("resolve_target: failed to list access policies for prefilter lookup: %s", exc)
        return None

    for pol in policies or []:
        if _normalize_id(pol.get("id")) != pid:
            continue
        setting = pol.get("prefilterPolicySetting")
        if isinstance(setting, dict):
            candidate = _prefilter_from_setting(setting)
            if candidate:
                return candidate
    return None


async def resolve_target(client: Any, target: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Resolve a target string into one FMC object (device record OR HA pair OR cluster).

    Returns (raw_object, note).
    """
    t = _safe_lower(target)
    if not t:
        return None, "empty_target"

    # 1) Device records
    try:
        devices = await client.list_device_records()
    except Exception as e:
        return None, f"failed_list_device_records={e!r}"

    exact_matches = [d for d in (devices or []) if isinstance(d, dict) and _match_target_record(t, d)]
    if len(exact_matches) == 1:
        return exact_matches[0], "resolved_as=device"
    if len(exact_matches) > 1:
        names = [m.get("name") for m in exact_matches][:10]
        return None, f"multiple_device_matches={names!r}"

    fuzzy_matches = [d for d in (devices or []) if isinstance(d, dict) and _contains_target_record(t, d)]
    if len(fuzzy_matches) == 1:
        return fuzzy_matches[0], "resolved_as=device(fuzzy)"
    if len(fuzzy_matches) > 1:
        names = [m.get("name") for m in fuzzy_matches][:10]
        return None, f"multiple_device_fuzzy_matches={names!r}"

    # 2) HA pairs
    try:
        ha_pairs = await client.list_device_ha_pairs()
    except Exception:
        ha_pairs = []

    ha_exact = [h for h in (ha_pairs or []) if isinstance(h, dict) and _match_target_record(t, h)]
    if len(ha_exact) == 1:
        return ha_exact[0], "resolved_as=ha"
    if len(ha_exact) > 1:
        names = [m.get("name") for m in ha_exact][:10]
        return None, f"multiple_ha_matches={names!r}"

    ha_fuzzy = [h for h in (ha_pairs or []) if isinstance(h, dict) and _contains_target_record(t, h)]
    if len(ha_fuzzy) == 1:
        return ha_fuzzy[0], "resolved_as=ha(fuzzy)"
    if len(ha_fuzzy) > 1:
        names = [m.get("name") for m in ha_fuzzy][:10]
        return None, f"multiple_ha_fuzzy_matches={names!r}"

    # 3) Clusters
    try:
        clusters = await client.list_device_clusters()
    except Exception:
        clusters = []

    cl_exact = [c for c in (clusters or []) if isinstance(c, dict) and _match_target_record(t, c)]
    if len(cl_exact) == 1:
        return cl_exact[0], "resolved_as=cluster"
    if len(cl_exact) > 1:
        names = [m.get("name") for m in cl_exact][:10]
        return None, f"multiple_cluster_matches={names!r}"

    cl_fuzzy = [c for c in (clusters or []) if isinstance(c, dict) and _contains_target_record(t, c)]
    if len(cl_fuzzy) == 1:
        return cl_fuzzy[0], "resolved_as=cluster(fuzzy)"
    if len(cl_fuzzy) > 1:
        names = [m.get("name") for m in cl_fuzzy][:10]
        return None, f"multiple_cluster_fuzzy_matches={names!r}"

    # Nothing matched
    sample_names = [d.get("name") for d in (devices or []) if isinstance(d, dict) and d.get("name")][:10]
    return None, f"no_match(target={target!r}, sample_device_names={sample_names!r})"


async def resolve_target_policies(client: Any, target: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Resolve target -> determine Access + Prefilter policies.

    Strategy:
    - Resolve target to a raw object (device/HA/cluster)
    - Extract policy refs directly if present
    - If missing: for HA/cluster, look up member device records and extract from those
    - If prefilter missing but access is known: fetch access policy (expanded) and use prefilterPolicySetting
    """
    raw, note = await resolve_target(client, target)
    if not raw:
        return None, f"Unable to resolve target {target!r} to device/HA/cluster ({note})"

    access_pol, prefilter_pol = _extract_policies_from_resolved_target(raw)

    candidate_ids: Set[str] = set()
    resolved_id = raw.get("id")
    if resolved_id:
        norm = _normalize_id(resolved_id)
        if norm:
            candidate_ids.add(norm)

    # If HA/cluster doesn't carry policy refs directly, try member devices
    member_ids = _extract_member_device_ids(raw)
    if member_ids and (not access_pol or not prefilter_pol):
        for did in member_ids[:5]:
            try:
                dr = await client.get_device_record(did, expanded=True)
            except Exception:
                continue
            ap2, pp2 = _extract_policies_from_resolved_target(dr)
            if not access_pol and ap2:
                access_pol = ap2
            if not prefilter_pol and pp2:
                prefilter_pol = pp2
            if access_pol and prefilter_pol:
                break
        for mid in member_ids:
            normalized = _normalize_id(mid)
            if normalized:
                candidate_ids.add(normalized)

    if candidate_ids and (not access_pol or not prefilter_pol):
        access_pol, prefilter_pol = await _fill_policies_from_assignments(
            client, candidate_ids, access_pol, prefilter_pol
        )

    # If we have access policy but not prefilter, derive it from AccessPolicy.prefilterPolicySetting
    if access_pol and not prefilter_pol:
        try:
            ap_full = await client.get_access_policy(access_pol["id"], expanded=True)
        except Exception as exc:
            logger.warning("resolve_target: get_access_policy failed for %s: %s", access_pol["id"], exc)
            ap_full = {}

        if isinstance(ap_full, dict):
            candidate = _prefilter_from_setting(ap_full.get("prefilterPolicySetting"))
            if candidate:
                prefilter_pol = candidate

    if access_pol and not prefilter_pol:
        candidate = await _prefilter_from_access_listing(client, access_pol["id"])
        if candidate:
            prefilter_pol = candidate

    resolved = {
        "target": target,
        "resolved_target": {
            "target_type": raw.get("type") or raw.get("targetType") or "unknown",
            "target_id": raw.get("id"),
            "name": raw.get("name"),
            "hostName": raw.get("hostName") or raw.get("hostname"),
        },
        "access_policy": access_pol,
        "prefilter_policy": prefilter_pol,
    }

    if not access_pol and not prefilter_pol:
        return None, f"Resolved target but could not determine policies (note={note})"

    return resolved, note
