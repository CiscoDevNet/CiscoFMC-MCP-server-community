# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..logging_conf import configure_logging
from .indicator import QueryKind, parse_literal_value

logger = configure_logging("sfw-mcp-fmc")


@dataclass
class AddressInterval:
    version: int
    start: int
    end: int


@dataclass
class NetworkObject:
    id: str
    name: str
    type: str
    intervals: List[AddressInterval] = field(default_factory=list)
    fqdns: List[str] = field(default_factory=list)
    member_ids: List[str] = field(default_factory=list)


class NetworkObjectIndex:
    def __init__(self) -> None:
        self.by_id: Dict[str, NetworkObject] = {}

    @staticmethod
    def _ip_to_interval(ip: ipaddress._BaseAddress) -> AddressInterval:
        return AddressInterval(version=ip.version, start=int(ip), end=int(ip))

    @staticmethod
    def _network_to_interval(net: ipaddress._BaseNetwork) -> AddressInterval:
        return AddressInterval(
            version=net.version,
            start=int(net.network_address),
            end=int(net.broadcast_address),
        )

    @staticmethod
    def _range_to_interval(
        start_ip: ipaddress._BaseAddress, end_ip: ipaddress._BaseAddress
    ) -> AddressInterval:
        if start_ip.version != end_ip.version:
            raise ValueError("IP range has mixed versions")
        s, e = int(start_ip), int(end_ip)
        if e < s:
            raise ValueError("IP range end < start")
        return AddressInterval(version=start_ip.version, start=s, end=e)

    def add_host(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        ip_str = obj.get("value")
        if not obj_id or not ip_str:
            return
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return
        self.by_id[obj_id] = NetworkObject(
            id=obj_id, name=name, type="Host", intervals=[self._ip_to_interval(ip)]
        )

    def add_network(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        value = obj.get("value")
        if not obj_id or not value:
            return
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return
        self.by_id[obj_id] = NetworkObject(
            id=obj_id, name=name, type="Network", intervals=[self._network_to_interval(net)]
        )

    def add_range(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        s = obj.get("startIpAddress")
        e = obj.get("endIpAddress")
        if not obj_id or not s or not e:
            return
        try:
            start_ip = ipaddress.ip_address(s)
            end_ip = ipaddress.ip_address(e)
            interval = self._range_to_interval(start_ip, end_ip)
        except ValueError:
            return
        self.by_id[obj_id] = NetworkObject(
            id=obj_id, name=name, type="Range", intervals=[interval]
        )

    def add_fqdn(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        value = obj.get("value")
        if not obj_id or not value:
            return
        self.by_id[obj_id] = NetworkObject(
            id=obj_id, name=name, type="FQDN", fqdns=[str(value).lower()]
        )

    def _add_literals_to_object(self, netobj: NetworkObject, literals: List[Dict[str, Any]]) -> None:
        for lit in literals:
            v = lit.get("value")
            if not v:
                continue
            lit_kind, lit_value = parse_literal_value(str(v))
            if lit_kind == QueryKind.IP:
                try:
                    ip = ipaddress.ip_address(str(lit_value))
                    netobj.intervals.append(self._ip_to_interval(ip))
                except ValueError:
                    continue
            elif lit_kind == QueryKind.NETWORK:
                try:
                    net = ipaddress.ip_network(str(lit_value), strict=False)
                    netobj.intervals.append(self._network_to_interval(net))
                except ValueError:
                    continue
            elif lit_kind == QueryKind.FQDN:
                netobj.fqdns.append(str(lit_value).lower())

    def add_network_group(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        if not obj_id:
            return

        netobj = NetworkObject(id=obj_id, name=name, type="NetworkGroup")
        for child in obj.get("objects") or []:
            cid = child.get("id")
            if cid:
                netobj.member_ids.append(cid)

        self._add_literals_to_object(netobj, obj.get("literals") or [])
        self.by_id[obj_id] = netobj

    def add_dynamic_object(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        if not obj_id:
            return

        netobj = NetworkObject(id=obj_id, name=name, type="DynamicObject")
        for child in obj.get("objects") or []:
            cid = child.get("id")
            if cid:
                netobj.member_ids.append(cid)

        self._add_literals_to_object(netobj, obj.get("literals") or [])
        self.by_id[obj_id] = netobj

    @staticmethod
    def _intervals_overlap(a: AddressInterval, b: AddressInterval) -> bool:
        if a.version != b.version:
            return False
        return not (a.end < b.start or b.end < a.start)

    def _build_query_intervals(self, query_kind: str, query_value: Any) -> List[AddressInterval]:
        if query_kind == QueryKind.IP:
            return [self._ip_to_interval(query_value)]
        if query_kind == QueryKind.NETWORK:
            return [self._network_to_interval(query_value)]
        return []

    def _object_matches(
        self,
        netobj: NetworkObject,
        query_kind: str,
        query_value: Any,
        query_intervals: List[AddressInterval],
        visited: Optional[Set[str]] = None,
    ) -> bool:
        if visited is None:
            visited = set()
        if netobj.id in visited:
            return False
        visited.add(netobj.id)

        if query_kind in {QueryKind.IP, QueryKind.NETWORK} and query_intervals:
            for obj_interval in netobj.intervals:
                for q_interval in query_intervals:
                    if self._intervals_overlap(obj_interval, q_interval):
                        return True

        if query_kind == QueryKind.FQDN and netobj.fqdns:
            if query_value in netobj.fqdns:
                return True

        for member_id in netobj.member_ids:
            child = self.by_id.get(member_id)
            if child and self._object_matches(child, query_kind, query_value, query_intervals, visited):
                return True

        return False

    def match_objects(self, query_kind: str, query_value: Any) -> List[NetworkObject]:
        results: List[NetworkObject] = []
        q_intervals = self._build_query_intervals(query_kind, query_value)
        for obj in self.by_id.values():
            try:
                if self._object_matches(obj, query_kind, query_value, q_intervals):
                    results.append(obj)
            except Exception:
                continue
        return results
