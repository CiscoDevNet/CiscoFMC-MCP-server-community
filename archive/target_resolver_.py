from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..logging_conf import configure_logging
from ..fmc.client import FMCClient

logger = configure_logging("sfw-mcp-fmc")


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _policy_type_of(item: Dict[str, Any]) -> str:
    pol = item.get("policy") or {}
    return (pol.get("type") or pol.get("policyType") or "").strip()


def _target_ids_of(item: Dict[str, Any]) -> List[str]:
    targets = item.get("targets") or []
    ids: List[str] = []
    for t in targets:
        tid = (t.get("id") or "").strip()
        if tid:
            ids.append(tid)
    return ids


async def resolve_target_policies(
    client: FMCClient, target: str
) -> Tuple[Dict[str, Any], str]:
    """
    Resolve a target (device/HA/cluster) to policies assigned:
      - AccessPolicy
      - PrefilterPolicy
    """
    target_norm = _norm(target)

    devs = await client.list_device_records()
    ha_pairs = await client.list_device_ha_pairs()   # safe (404 ignored in client)
    clusters = await client.list_device_clusters()   # safe (404 ignored in client)
    assignments = await client.list_policy_assignments()

    resolved: Optional[Dict[str, Any]] = None
    resolved_type: str = "Device"

    # DeviceRecord match by name/hostName
    for d in devs:
        if _norm(d.get("name")) == target_norm or _norm(d.get("hostName")) == target_norm:
            resolved = d
            resolved_type = "Device"
            break

    # HA pair match by name
    if not resolved:
        for ha in ha_pairs:
            if _norm(ha.get("name")) == target_norm:
                resolved = ha
                resolved_type = "HA"
                break

    # Cluster match by name
    if not resolved:
        for cl in clusters:
            if _norm(cl.get("name")) == target_norm:
                resolved = cl
                resolved_type = "Cluster"
                break

    if not resolved:
        raise ValueError(f"Target '{target}' not found (no device/HA/cluster matched).")

    resolved_id = (resolved.get("id") or "").strip()
    if not resolved_id:
        raise ValueError(f"Resolved target '{target}' has no id.")

    candidate_ids = {resolved_id}

    # best-effort include member ids (varies by endpoint/shape)
    for key in ("devices", "members"):
        for m in (resolved.get(key) or []):
            mid = (m.get("id") or "").strip()
            if mid:
                candidate_ids.add(mid)

    access_pol: Optional[Dict[str, Any]] = None
    prefilter_pol: Optional[Dict[str, Any]] = None

    for a in assignments:
        tids = set(_target_ids_of(a))
        if not tids.intersection(candidate_ids):
            continue

        pol = a.get("policy") or {}
        pol_id = (pol.get("id") or "").strip()
        if not pol_id:
            continue

        ptype = _policy_type_of(a)
        if ptype in ("AccessPolicy", "AccessControlPolicy"):
            access_pol = {"id": pol_id, "name": pol.get("name"), "type": "AccessPolicy"}
        elif ptype in ("PrefilterPolicy",):
            prefilter_pol = {"id": pol_id, "name": pol.get("name"), "type": "PrefilterPolicy"}

    note = (
        f"resolved_as={resolved_type}; "
        f"candidate_ids={len(candidate_ids)}; "
        f"access_policy={'YES' if access_pol else 'NO'}; "
        f"prefilter_policy={'YES' if prefilter_pol else 'NO'}"
    )

    resolved_out = {
        "target_type": resolved_type,
        "id": resolved_id,
        "name": resolved.get("name") or resolved.get("hostName") or target,
        "access_policy": access_pol,
        "prefilter_policy": prefilter_pol,
    }
    return resolved_out, note


# Backward compatible wrapper (if anything still imports it)
async def resolve_target_to_access_policy(
    client: FMCClient, target: str
) -> Tuple[Dict[str, Any], str]:
    resolved, note = await resolve_target_policies(client, target)
    ap = resolved.get("access_policy")
    if not ap or not ap.get("id"):
        raise ValueError(f"Target '{target}' has no Access Policy assignment.")
    return {"access_policy": ap, "target_type": resolved.get("target_type"), "target_id": resolved.get("id")}, note
