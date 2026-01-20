# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, List, Optional

from ..logging_conf import configure_logging
from ..match.indicator import QueryKind, classify_indicator, collect_matching_literals
from ..match.network_index import NetworkObjectIndex
from ..fmc.client import FMCClient

logger = configure_logging("sfw-mcp-fmc")

_VERBS = (
    "ingest",
    "add",
    "index",
    "load",
    "register",
    "append",
    "extend",
    "put",
    "set",
    "build",
)


def serialize_network_object(obj: Any) -> Dict[str, Any]:
    # Imported by search_access.py — keep stable
    if isinstance(obj, dict):
        return {
            "id": obj.get("id"),
            "name": obj.get("name"),
            "type": obj.get("type"),
            "value": obj.get("value") or obj.get("dnsName"),
        }
    return {
        "id": getattr(obj, "id", None),
        "name": getattr(obj, "name", None),
        "type": getattr(obj, "type", None),
        "value": getattr(obj, "value", None),
    }


def _extract_value(item: Dict[str, Any]) -> Any:
    # FMC object fields vary by type
    return (
        item.get("value")
        or item.get("dnsName")
        or item.get("fqdn")
        or item.get("ip")
        or item.get("address")
    )


def _is_singular_method_name(method_name: str) -> bool:
    n = method_name.lower()
    # add_host (singular) vs add_hosts (plural)
    if n.endswith("s"):
        return False
    if n.startswith("add_"):
        return True
    return False


def _call_bulk(fn: Callable[..., Any], payload: List[Dict[str, Any]]) -> bool:
    # bulk: fn(list)
    try:
        fn(payload)
        return True
    except TypeError:
        pass
    except Exception:
        return False

    # bulk: fn(items=list)
    try:
        fn(items=payload)  # type: ignore
        return True
    except Exception:
        return False


def _call_single_with_signature(fn: Callable[..., Any], item: Dict[str, Any]) -> bool:
    """
    Call fn with arguments inferred from its signature.
    Supports patterns like:
      add_host(obj)
      add_host(host)
      add_host(item=...)
      add_host(name, value, id, type)
      add_host(name=..., value=..., id=..., type=...)
    """
    try:
        sig = inspect.signature(fn)
    except Exception:
        # last resort
        try:
            fn(item)
            return True
        except Exception:
            return False

    params = [p for p in sig.parameters.values() if p.name != "self"]
    param_names = [p.name for p in params]

    # Fast path: single arg, accept dict directly or as named
    if len(params) == 1:
        p0 = params[0]
        # 1) positional dict
        try:
            fn(item)
            return True
        except TypeError:
            pass
        except Exception:
            return False

        # 2) keyword: fn(host=item) / fn(obj=item) / fn(item=item)
        try:
            fn(**{p0.name: item})
            return True
        except Exception:
            return False

    # Build kwargs from known fields
    name = item.get("name")
    value = _extract_value(item)
    oid = item.get("id")
    otype = item.get("type")

    # If signature accepts **kwargs, we can pass a filtered dict
    accepts_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

    candidates: Dict[str, Any] = {}

    # Common param-name mappings
    for p in param_names:
        pl = p.lower()
        if p in item:
            candidates[p] = item[p]
            continue
        if pl in ("name", "objname"):
            candidates[p] = name
            continue
        if pl in ("value", "ip", "address", "addr", "host", "hostname", "fqdn", "dnsname"):
            # for host/network/range -> value; for fqdn -> dnsName
            candidates[p] = value if value is not None else name
            continue
        if pl in ("id", "uuid", "objectid"):
            candidates[p] = oid
            continue
        if pl in ("type", "objtype", "objecttype"):
            candidates[p] = otype
            continue
        if pl in ("obj", "object", "item", "host", "network", "range", "fqdn", "group", "dynamic"):
            candidates[p] = item
            continue

    # Try keyword-only call with filtered args
    filtered = {k: v for k, v in candidates.items() if v is not None}

    if filtered:
        try:
            fn(**filtered)
            return True
        except TypeError:
            pass
        except Exception:
            return False

    # Try positional call (name, value, id, type) in that order if matches
    positional_pool = [name, value, oid, otype]
    try:
        # Only pass as many positional args as function requires (excluding defaults)
        required = [
            p for p in params
            if p.default is inspect._empty and p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        nreq = len(required)
        if nreq > 0:
            fn(*[x for x in positional_pool[:nreq]])
            return True
    except TypeError:
        pass
    except Exception:
        return False

    # If accepts **kwargs, last resort: pass whole item
    if accepts_varkw:
        try:
            fn(**item)
            return True
        except Exception:
            return False

    return False


def _call_maybe(fn: Callable[..., Any], payload: List[Dict[str, Any]], *, method_name: str) -> bool:
    # Try bulk styles first
    if _call_bulk(fn, payload):
        return True

    # If singular (e.g. add_host), call per-item using signature inference
    if _is_singular_method_name(method_name):
        ok_any = False
        for item in payload:
            if not isinstance(item, dict):
                # nothing we can do
                return False
            ok = _call_single_with_signature(fn, item)
            if not ok:
                return False
            ok_any = True
        return ok_any

    return False


def _discover_and_ingest(
    idx: NetworkObjectIndex,
    *,
    noun: str,
    payload: List[Dict[str, Any]],
    exclude: Optional[List[str]] = None,
) -> str:
    exclude = exclude or []
    noun_l = noun.lower()

    candidates: List[str] = []
    for name in dir(idx):
        if name.startswith("_"):
            continue
        lname = name.lower()
        if any(x in lname for x in exclude):
            continue
        if noun_l not in lname:
            continue
        if not any(v in lname for v in _VERBS):
            continue
        fn = getattr(idx, name, None)
        if callable(fn):
            candidates.append(name)

    candidates.sort()

    last_err: Optional[str] = None
    for name in candidates:
        fn = getattr(idx, name)
        try:
            if _call_maybe(fn, payload, method_name=name):
                return name
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    raise AttributeError(
        f"NetworkObjectIndex has no compatible ingest method for '{noun}'. "
        f"Found candidates={candidates}. LastError={last_err}"
    )


def _try_generic_bulk_ingest(
    idx: NetworkObjectIndex,
    *,
    hosts: List[Dict[str, Any]],
    networks: List[Dict[str, Any]],
    ranges: List[Dict[str, Any]],
    fqdns: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    dynamics: List[Dict[str, Any]],
) -> Optional[str]:
    bulk_names = [
        "ingest",
        "ingest_all",
        "load_all",
        "index_all",
        "build_index",
        "from_objects",
        "load",
        "build",
    ]

    for name in bulk_names:
        fn = getattr(idx, name, None)
        if not callable(fn):
            continue

        try:
            fn(
                hosts=hosts,
                networks=networks,
                ranges=ranges,
                fqdns=fqdns,
                groups=groups,
                dynamics=dynamics,
            )
            return name
        except TypeError:
            pass
        except Exception:
            continue

        try:
            fn(
                {
                    "hosts": hosts,
                    "networks": networks,
                    "ranges": ranges,
                    "fqdns": fqdns,
                    "groups": groups,
                    "dynamics": dynamics,
                }
            )
            return name
        except Exception:
            continue

    return None


async def build_object_index(client: FMCClient) -> NetworkObjectIndex:
    hosts = await client.list_host_objects()
    nets = await client.list_network_objects()
    ranges = await client.list_range_objects()
    fqdns = await client.list_fqdn_objects()
    groups = await client.list_network_groups()
    dynamics = await client.list_dynamic_objects(hard_page_limit=5)

    idx = NetworkObjectIndex()

    used_bulk = _try_generic_bulk_ingest(
        idx,
        hosts=hosts,
        networks=nets,
        ranges=ranges,
        fqdns=fqdns,
        groups=groups,
        dynamics=dynamics,
    )

    if used_bulk:
        logger.info("Indexed objects via bulk loader: %s", used_bulk)
    else:
        used_hosts = _discover_and_ingest(idx, noun="host", payload=hosts)
        used_nets = _discover_and_ingest(idx, noun="network", payload=nets, exclude=["group"])
        used_ranges = _discover_and_ingest(idx, noun="range", payload=ranges)
        used_fqdns = _discover_and_ingest(idx, noun="fqdn", payload=fqdns)
        used_groups = _discover_and_ingest(idx, noun="group", payload=groups)
        used_dyn = _discover_and_ingest(idx, noun="dynamic", payload=dynamics)

        logger.info(
            "Indexed objects via discovered loaders: host=%s network=%s range=%s fqdn=%s group=%s dynamic=%s",
            used_hosts,
            used_nets,
            used_ranges,
            used_fqdns,
            used_groups,
            used_dyn,
        )

    logger.info(
        "Fetched objects: hosts=%s networks=%s ranges=%s fqdns=%s groups=%s dynamics=%s",
        len(hosts),
        len(nets),
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
    kind, value = classify_indicator(query, "auto")
    idx = await build_object_index(client)

    matching_objects = idx.match_objects(kind, value)
    matched_ids = {serialize_network_object(o).get("id") for o in matching_objects}
    matched_ids.discard(None)

    rules = await client.list_access_rules(access_policy_id, expanded=True)

    items: List[Dict[str, Any]] = []
    for rule in rules:
        src = (rule.get("sourceNetworks") or {}).copy()
        dst = (rule.get("destinationNetworks") or {}).copy()

        src_lit = collect_matching_literals(kind, value, src)
        dst_lit = collect_matching_literals(kind, value, dst)

        src_obj: List[Dict[str, Any]] = []
        dst_obj: List[Dict[str, Any]] = []

        for ref in src.get("objects") or []:
            rid = ref.get("id")
            if rid and rid in matched_ids:
                src_obj.append({"id": rid, "name": ref.get("name"), "type": ref.get("type")})

        for ref in dst.get("objects") or []:
            rid = ref.get("id")
            if rid and rid in matched_ids:
                dst_obj.append({"id": rid, "name": ref.get("name"), "type": ref.get("type")})

        if not (src_lit or dst_lit or src_obj or dst_obj):
            continue

        items.append(
            {
                "rule": {
                    "id": rule.get("id"),
                    "name": rule.get("name"),
                    "action": rule.get("action"),
                    "enabled": rule.get("enabled", True),
                    "metadata": rule.get("metadata", {}),
                    "source_literal_matches": src_lit,
                    "destination_literal_matches": dst_lit,
                    "source_object_matches": src_obj,
                    "destination_object_matches": dst_obj,
                }
            }
        )

    return {
        "meta": {
            "query": query,
            "query_kind": "ip"
            if kind == QueryKind.IP
            else "subnet"
            if kind == QueryKind.NETWORK
            else "fqdn",
            "matched_object_count": len(matching_objects),
            "matched_rules_count": len(items),
            "policy_id": access_policy_id,
            "policy_type": "AccessPolicy",
        },
        "items": items,
    }
