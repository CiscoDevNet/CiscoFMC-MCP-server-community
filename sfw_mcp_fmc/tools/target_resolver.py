from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..fmc.client import FMCClient


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


async def resolve_target_to_access_policy(
    client: FMCClient, target: str
) -> Tuple[Dict[str, Any], str]:
    """
    Resolve device/HA/cluster target to an AccessPolicy reference.

    Returns:
      (resolved_device_dict, resolution_note)

    resolved_device_dict includes:
      - kind, id, name, hostName
      - access_policy: {id, name, type}
    """
    devices = await client.list_device_records()
    ha_pairs = await client.list_device_ha_pairs()
    clusters = await client.list_device_clusters()

    candidates: List[Dict[str, Any]] = (
        [{"kind": "device", "record": d} for d in devices]
        + [{"kind": "ha", "record": h} for h in ha_pairs]
        + [{"kind": "cluster", "record": c} for c in clusters]
    )

    norm_target = _norm(target)
    exact: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []

    for cand in candidates:
        r = cand["record"]
        name = _norm(r.get("name"))
        host = _norm(r.get("hostName"))

        if norm_target == name or (host and norm_target == host):
            exact.append(cand)
        elif norm_target and (norm_target in name or (host and norm_target in host)):
            partial.append(cand)

    if not exact and not partial:
        raise ValueError(f"No device/HA/cluster record matched target '{target}'.")

    chosen = (exact or partial)[0]
    kinds = sorted({c["kind"] for c in (exact or partial)})
    resolution_note = "Exact match by name/hostName." if exact else "Partial match by name/hostName."
    if len(exact or partial) > 1 or len(kinds) > 1:
        resolution_note = f"{resolution_note} Multiple matches (kinds={kinds}), picked the first."

    origin_kind = chosen["kind"]
    record = chosen["record"]

    device_id = record.get("id")
    if not device_id:
        raise ValueError(f"Chosen record for target '{target}' has no id; cannot resolve policy.")

    policy = (record.get("accessPolicy") or {}).copy()

    if not policy or policy.get("type") != "AccessPolicy":
        assignments = await client.list_policy_assignments()
        access_assignments: List[Dict[str, Any]] = []
        for assign in assignments:
            pol = assign.get("policy") or {}
            if pol.get("type") != "AccessPolicy":
                continue
            for t in assign.get("targets") or []:
                if t.get("id") == device_id:
                    access_assignments.append(assign)

        if not access_assignments:
            raise ValueError(f"No Access Policy assignment found for target '{target}'.")

        policy = (access_assignments[0].get("policy") or {}).copy()

    if not policy or policy.get("type") != "AccessPolicy" or not policy.get("id"):
        raise ValueError(f"Could not resolve Access Policy for target '{target}'.")

    return (
        {
            "kind": origin_kind,
            "id": device_id,
            "name": record.get("name"),
            "hostName": record.get("hostName"),
            "access_policy": {
                "id": policy.get("id"),
                "name": policy.get("name"),
                "type": policy.get("type"),
            },
        },
        resolution_note,
    )
