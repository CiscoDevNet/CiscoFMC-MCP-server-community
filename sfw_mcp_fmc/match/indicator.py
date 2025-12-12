from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from ..errors import InvalidIndicatorError

# Stricter FQDN: at least one dot, labels 1–63 chars, and last label letters only (2+)
FQDN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)


class QueryKind:
    IP = "ip"
    NETWORK = "network"
    FQDN = "fqdn"


def parse_query(query: str) -> Tuple[str, Any]:
    q = query.strip()
    try:
        if "/" in q:
            net = ipaddress.ip_network(q, strict=False)
            return (QueryKind.NETWORK, net)
        ip = ipaddress.ip_address(q)
        return (QueryKind.IP, ip)
    except ValueError:
        return (QueryKind.FQDN, q.lower())


def parse_literal_value(value: str) -> Tuple[str, Any]:
    v = value.strip()
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            return (QueryKind.NETWORK, net)
        ip = ipaddress.ip_address(v)
        return (QueryKind.IP, ip)
    except ValueError:
        return (QueryKind.FQDN, v.lower())


def classify_indicator(indicator: str, indicator_type: str = "auto") -> Tuple[str, Any]:
    kind, value = parse_query(indicator)
    value_str = str(value)

    looks_like_ipv4 = bool(re.fullmatch(r"\d+(\.\d+){1,3}", indicator.strip()))

    if kind == QueryKind.FQDN:
        has_alpha = bool(re.search(r"[A-Za-z]", value_str))
        if indicator_type == "auto":
            if looks_like_ipv4 or not has_alpha or not FQDN_PATTERN.match(value_str):
                raise InvalidIndicatorError(f"'{indicator}' is not a valid IP, CIDR, or FQDN.")
        else:
            if not has_alpha or not FQDN_PATTERN.match(value_str):
                raise InvalidIndicatorError(f"'{indicator}' is not a syntactically valid FQDN.")

    if indicator_type == "auto":
        return kind, value
    if indicator_type == "ip" and kind == QueryKind.IP:
        return kind, value
    if indicator_type == "subnet" and kind == QueryKind.NETWORK:
        return kind, value
    if indicator_type == "fqdn" and kind == QueryKind.FQDN:
        return kind, value

    raise InvalidIndicatorError(
        f"Expected {indicator_type} but got '{kind}' for '{indicator}'. "
        "Use 'auto', 'ip', 'subnet', or 'fqdn'."
    )


def literal_matches(query_kind: str, query_value: Any, literal: Dict[str, Any]) -> bool:
    raw_value = str(literal.get("value", "")).strip()
    if not raw_value:
        return False

    lit_kind, lit_value = parse_literal_value(raw_value)

    if query_kind == QueryKind.IP:
        if lit_kind == QueryKind.IP:
            return query_value == lit_value
        if lit_kind == QueryKind.NETWORK:
            return query_value in lit_value
        return False

    if query_kind == QueryKind.NETWORK:
        if lit_kind == QueryKind.IP:
            return lit_value in query_value
        if lit_kind == QueryKind.NETWORK:
            return query_value.overlaps(lit_value)
        return False

    if query_kind == QueryKind.FQDN:
        return raw_value.lower() == query_value

    return query_value in raw_value


def collect_matching_literals(
    query_kind: str, query_value: Any, network_block: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if not network_block:
        return []
    matches: List[Dict[str, Any]] = []
    for lit in network_block.get("literals") or []:
        if literal_matches(query_kind, query_value, lit):
            matches.append(lit)
    return matches
