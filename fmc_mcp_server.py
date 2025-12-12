#!/usr/bin/env python3
"""
Cisco Secure Firewall FMC MCP server

FastMCP-based MCP server that exposes tools to:
- Find rules by IP/CIDR/FQDN within a specific Access Policy
- Resolve an FTD/cluster target to its Access Policy and search rules
- FMC-centric search across Access Policies (search_access_rules)

Assumptions:
- FastMCP 2.x-style usage with @mcp.tool() decorators.
- No FastMCP constructor extras (description/version) – compatible
  with the version installed in the container.
"""

import asyncio
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from fastmcp import FastMCP

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("fmc-mcp")

# -----------------------------------------------------------------------------
# Environment / FMC config
# -----------------------------------------------------------------------------
FMC_BASE_URL = os.getenv("FMC_BASE_URL", "").rstrip("/")
FMC_USERNAME = os.getenv("FMC_USERNAME")
FMC_PASSWORD = os.getenv("FMC_PASSWORD")
FMC_DOMAIN_UUID = os.getenv("FMC_DOMAIN_UUID")  # optional override
FMC_VERIFY_SSL = os.getenv("FMC_VERIFY_SSL", "false").lower() == "true"
FMC_TIMEOUT = float(os.getenv("FMC_TIMEOUT", "30"))

if not FMC_BASE_URL or not FMC_USERNAME or not FMC_PASSWORD:
    logger.warning(
        "FMC_BASE_URL, FMC_USERNAME, or FMC_PASSWORD not fully set in environment. "
        "Tools will fail if FMC access is required."
    )

# -----------------------------------------------------------------------------
# HTTP / FMC client helpers
# -----------------------------------------------------------------------------
@dataclass
class FMCAuthToken:
    token: str
    refresh_token: Optional[str]
    domain_uuid: Optional[str]


class FMCClientError(Exception):
    """Custom exception for FMC client errors."""


class FMCClient:
    """
    Simple synchronous FMC REST client using httpx.Client.

    This is used inside FastMCP tools, which are synchronous functions.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
        default_domain_uuid: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.default_domain_uuid = default_domain_uuid

        self._client = httpx.Client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        self._auth_token: Optional[FMCAuthToken] = None
        self._logger = logging.getLogger("FMCClient")

    # --------------------------- Auth / Tokens ---------------------------

    def _authenticate(self) -> FMCAuthToken:
        """
        Acquire a new FMC auth token.
        """
        self._logger.debug("Authenticating to FMC...")
        url = "/api/fmc_platform/v1/auth/generatetoken"
        resp = self._client.post(url, auth=(self.username, self.password))

        if resp.status_code not in (200, 204):
            raise FMCClientError(
                f"Failed to authenticate to FMC: {resp.status_code} {resp.text}"
            )

        headers = resp.headers
        access_token = headers.get("X-auth-access-token")
        refresh_token = headers.get("X-auth-refresh-token")
        domain_uuid = headers.get("DOMAIN_UUID")

        if not access_token:
            raise FMCClientError("FMC did not return X-auth-access-token header")

        token = FMCAuthToken(
            token=access_token,
            refresh_token=refresh_token,
            domain_uuid=domain_uuid,
        )
        self._auth_token = token
        self._logger.info(
            "Authenticated to FMC. Domain UUID from token: %s", domain_uuid
        )
        return token

    def _ensure_token(self) -> FMCAuthToken:
        if self._auth_token is None:
            return self._authenticate()
        return self._auth_token

    # --------------------------- Domain helpers --------------------------

    def get_effective_domain_uuid(self, override: Optional[str] = None) -> str:
        """
        Resolve the domain UUID to use for config calls:

        - If override is provided, use that.
        - Else, if environment default is set, use that.
        - Else, if token has a DOMAIN_UUID header, use that.
        - Else, query /api/fmc_platform/v1/info/domain and pick the Global domain.
        """
        if override:
            return override
        if self.default_domain_uuid:
            return self.default_domain_uuid

        token = self._ensure_token()
        if token.domain_uuid:
            return token.domain_uuid

        # Last resort: query the domain info
        self._logger.debug("Resolving domain UUID via /info/domain")
        resp = self._request(
            "GET",
            "/api/fmc_platform/v1/info/domain",
            use_config_api=False,
            include_domain=False,
        )
        items = resp.get("items", [])
        if not items:
            raise FMCClientError("No domains returned from FMC /info/domain")

        # Prefer Global domain if present
        for d in items:
            if d.get("name") == "Global":
                return d["id"]

        # Otherwise fall back to the first domain
        return items[0]["id"]

    # -------------------------- Low-level request ------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        domain_uuid: Optional[str] = None,
        use_config_api: bool = True,
        include_domain: bool = True,
    ) -> Dict[str, Any]:
        """
        Make an FMC REST call with automatic token handling.

        If use_config_api=True, path is assumed relative to /api/fmc_config/v1.
        If include_domain=True, we inject /domain/{uuid} into the path.
        """

        # Build base API prefix
        if use_config_api:
            api_prefix = "/api/fmc_config/v1"
        else:
            api_prefix = "/api/fmc_platform/v1"

        # Domain injection
        if include_domain:
            dom = self.get_effective_domain_uuid(domain_uuid)
            if not path.startswith("/"):
                path = "/" + path
            path = f"{api_prefix}/domain/{dom}{path}"
        else:
            if not path.startswith("/"):
                path = "/" + path
            path = f"{api_prefix}{path}"

        self._logger.debug("FMC request: %s %s params=%s", method, path, params)

        token = self._ensure_token()
        headers = {"X-auth-access-token": token.token}

        resp = self._client.request(
            method,
            path,
            params=params,
            json=json_body,
            headers=headers,
        )

        # Token expired?
        if resp.status_code == 401:
            self._logger.info("Token expired, re-authenticating...")
            self._authenticate()
            token = self._auth_token
            headers = {"X-auth-access-token": token.token}
            resp = self._client.request(
                method,
                path,
                params=params,
                json=json_body,
                headers=headers,
            )

        if resp.status_code not in (200, 201, 202, 204):
            raise FMCClientError(
                f"FMC API error: {resp.status_code} {resp.text}"
            )

        if resp.status_code == 204:
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {}

    # --------------------------- FMC helpers -----------------------------

    def list_access_policies(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        Return all Access Policies in the given domain.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 50

        while True:
            params = {"offset": offset, "limit": limit}
            data = self._request(
                "GET",
                "/policy/accesspolicies",
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items

    def list_access_rules_for_policy(
        self,
        policy_id: str,
        domain_uuid: Optional[str] = None,
        expanded: bool = True,
    ) -> List[Dict]:
        """
        Return all Access Rules for the given Access Policy.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 50

        while True:
            params = {"offset": offset, "limit": limit}
            if expanded:
                params["expanded"] = "true"
            data = self._request(
                "GET",
                f"/policy/accesspolicies/{policy_id}/accessrules",
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items

    def list_devices(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        Return all devices (FTDs) known to FMC.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 50

        while True:
            params = {"offset": offset, "limit": limit}
            data = self._request(
                "GET",
                "/device/devicerecords",
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items

    def get_device(self, device_id: str, domain_uuid: Optional[str] = None) -> Dict:
        """
        Get details for a single device.
        """
        return self._request(
            "GET",
            f"/device/devicerecords/{device_id}",
            domain_uuid=domain_uuid,
        )

    def list_device_ha_pairs(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        Return all HA pairs.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 50

        while True:
            params = {"offset": offset, "limit": limit}
            data = self._request(
                "GET",
                "/device/ftddevicehapairs",
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items

    def list_device_clusters(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        Return all FTD clusters.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 50

        while True:
            params = {"offset": offset, "limit": limit}
            data = self._request(
                "GET",
                "/device/ftddevicecluster",
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items

    def get_access_policy_for_device(
        self,
        device_id: str,
        domain_uuid: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Resolve which Access Policy is applied to the given device.
        """
        dev = self.get_device(device_id, domain_uuid=domain_uuid)
        acp = dev.get("accessPolicy")
        if not acp:
            return None
        return acp

    # Network objects
    def list_hosts(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        return self._list_paginated_objects("/object/hosts", domain_uuid)

    def list_networks(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        return self._list_paginated_objects("/object/networks", domain_uuid)

    def list_ranges(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        return self._list_paginated_objects("/object/ranges", domain_uuid)

    def list_fqdns(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        FMC FQDN objects (where available).
        """
        return self._list_paginated_objects("/object/fqdns", domain_uuid)

    def list_network_groups(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        return self._list_paginated_objects("/object/networkgroups", domain_uuid)

    def list_dynamic_objects(self, domain_uuid: Optional[str] = None) -> List[Dict]:
        """
        FMC Dynamic Objects.
        """
        return self._list_paginated_objects("/object/dynamicobjects", domain_uuid)

    def _list_paginated_objects(
        self,
        path: str,
        domain_uuid: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        items: List[Dict[str, Any]] = []
        offset = 0

        while True:
            params = {"offset": offset, "limit": limit}
            data = self._request(
                "GET",
                path,
                params=params,
                domain_uuid=domain_uuid,
            )
            batch = data.get("items", [])
            items.extend(batch)

            paging = data.get("paging") or {}
            total = paging.get("count", len(batch))
            if offset + limit >= total:
                break
            offset += limit

        return items


# Global singleton FMC client for tools
fmc_client = FMCClient(
    base_url=FMC_BASE_URL,
    username=FMC_USERNAME or "",
    password=FMC_PASSWORD or "",
    verify_ssl=FMC_VERIFY_SSL,
    timeout=FMC_TIMEOUT,
    default_domain_uuid=FMC_DOMAIN_UUID,
)

# -----------------------------------------------------------------------------
# Network object indexing / indicator classification
# -----------------------------------------------------------------------------

@dataclass
class IndexEntry:
    id: str
    name: str
    type: str
    kind: str  # "host", "network", "range", "fqdn", "group", "dynamic"
    value: Any


@dataclass
class NetworkObjectIndex:
    """
    Index of FMC network and FQDN objects.

    For now we handle:
      - Host
      - Network
      - Range
      - FQDN (FQDN objects)
      - NetworkGroup
      - DynamicObject
    """

    hosts_by_ip: Dict[str, List[IndexEntry]] = field(default_factory=dict)
    networks: List[Tuple[ipaddress._BaseNetwork, IndexEntry]] = field(
        default_factory=list
    )
    ranges: List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress, IndexEntry]] = field(
        default_factory=list
    )
    fqdns_by_name: Dict[str, List[IndexEntry]] = field(default_factory=dict)
    groups_by_id: Dict[str, IndexEntry] = field(default_factory=dict)
    dynamic_by_id: Dict[str, IndexEntry] = field(default_factory=dict)

    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger("NetworkObjectIndex")
    )

    # --------------- Construction helpers ---------------

    @classmethod
    def build_from_fmc(
        cls,
        client: FMCClient,
        domain_uuid: Optional[str] = None,
    ) -> "NetworkObjectIndex":
        """
        Build index by fetching FMC objects once.
        """
        logger = logging.getLogger("NetworkObjectIndex")
        logger.info("Building FMC network object index...")

        hosts = client.list_hosts(domain_uuid=domain_uuid)
        networks = client.list_networks(domain_uuid=domain_uuid)
        ranges = client.list_ranges(domain_uuid=domain_uuid)

        try:
            fqdns = client.list_fqdns(domain_uuid=domain_uuid)
        except FMCClientError:
            logger.warning("FMC FQDN endpoint not available, skipping.")
            fqdns = []

        groups = client.list_network_groups(domain_uuid=domain_uuid)
        try:
            dynamic = client.list_dynamic_objects(domain_uuid=domain_uuid)
        except FMCClientError:
            logger.warning("FMC dynamic objects endpoint not available, skipping.")
            dynamic = []

        index = cls()
        index.logger = logger

        for h in hosts:
            ip = h.get("value")
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            entry = IndexEntry(
                id=h["id"],
                name=h.get("name", ""),
                type=h["type"],
                kind="host",
                value=ip,
            )
            index.hosts_by_ip.setdefault(ip, []).append(entry)

        for n in networks:
            val = n.get("value")
            if not val:
                continue
            try:
                net = ipaddress.ip_network(val, strict=False)
            except ValueError:
                continue

            entry = IndexEntry(
                id=n["id"],
                name=n.get("name", ""),
                type=n["type"],
                kind="network",
                value=str(net),
            )
            index.networks.append((net, entry))

        for r in ranges:
            first_ip = r.get("value")
            last_ip = r.get("endValue") or r.get("valueEnd")
            if not first_ip or not last_ip:
                continue
            try:
                start = ipaddress.ip_address(first_ip)
                end = ipaddress.ip_address(last_ip)
            except ValueError:
                continue

            entry = IndexEntry(
                id=r["id"],
                name=r.get("name", ""),
                type=r["type"],
                kind="range",
                value=(str(start), str(end)),
            )
            index.ranges.append((start, end, entry))

        for f in fqdns:
            fqdn_value = f.get("fqdn") or f.get("value") or f.get("name")
            if not fqdn_value:
                continue
            fqdn_norm = fqdn_value.lower().rstrip(".")
            entry = IndexEntry(
                id=f["id"],
                name=f.get("name", ""),
                type=f["type"],
                kind="fqdn",
                value=fqdn_norm,
            )
            index.fqdns_by_name.setdefault(fqdn_norm, []).append(entry)

        for g in groups:
            entry = IndexEntry(
                id=g["id"],
                name=g.get("name", ""),
                type=g["type"],
                kind="group",
                value=g,
            )
            index.groups_by_id[entry.id] = entry

        for d in dynamic:
            entry = IndexEntry(
                id=d["id"],
                name=d.get("name", ""),
                type=d["type"],
                kind="dynamic",
                value=d,
            )
            index.dynamic_by_id[entry.id] = entry

        logger.info(
            "Network object index built: %d hosts, %d networks, %d ranges, "
            "%d FQDNs, %d groups, %d dynamic objects",
            len(index.hosts_by_ip),
            len(index.networks),
            len(index.ranges),
            len(index.fqdns_by_name),
            len(index.groups_by_id),
            len(index.dynamic_by_id),
        )

        return index

    # --------------- Matching helpers ---------------

    def classify_indicator(self, indicator: str) -> str:
        """
        Classify indicator as "ip", "network", or "fqdn".
        """
        # Try IP
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass

        # Try CIDR
        try:
            ipaddress.ip_network(indicator, strict=False)
            return "network"
        except ValueError:
            pass

        # Fallback to fqdn
        return "fqdn"

    def find_matches_for_indicator(self, indicator: str) -> Dict[str, Any]:
        """
        Return a dictionary of matched objects for the given indicator.
        """
        kind = self.classify_indicator(indicator)
        result: Dict[str, Any] = {
            "indicator": indicator,
            "indicator_type": kind,
            "matched_hosts": [],
            "matched_networks": [],
            "matched_ranges": [],
            "matched_fqdns": [],
            "matched_groups": [],
            "matched_dynamic_objects": [],
        }

        if kind == "ip":
            try:
                ip_obj = ipaddress.ip_address(indicator)
            except ValueError:
                return result

            # direct host match
            for entry in self.hosts_by_ip.get(indicator, []):
                result["matched_hosts"].append(entry.__dict__)

            # networks containing IP
            for net, entry in self.networks:
                if ip_obj in net:
                    result["matched_networks"].append(entry.__dict__)

            # ranges containing IP
            for start, end, entry in self.ranges:
                if start <= ip_obj <= end:
                    result["matched_ranges"].append(entry.__dict__)

        elif kind == "network":
            try:
                net_indicator = ipaddress.ip_network(indicator, strict=False)
            except ValueError:
                return result

            # hosts inside network
            for ip_str, entries in self.hosts_by_ip.items():
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj in net_indicator:
                    for e in entries:
                        result["matched_hosts"].append(e.__dict__)

            # overlapping networks
            for net, entry in self.networks:
                if net.overlaps(net_indicator):
                    result["matched_networks"].append(entry.__dict__)

            # ranges that intersect
            for start, end, entry in self.ranges:
                if start <= net_indicator.broadcast_address and end >= net_indicator.network_address:
                    result["matched_ranges"].append(entry.__dict__)

        else:  # fqdn
            fqdn_norm = indicator.lower().rstrip(".")
            for entry in self.fqdns_by_name.get(fqdn_norm, []):
                result["matched_fqdns"].append(entry.__dict__)

        return result


# -----------------------------------------------------------------------------
# Rule inspection helpers
# -----------------------------------------------------------------------------

def _extract_literal_ips(rule: Dict[str, Any], direction: str) -> List[str]:
    """
    Extract literal IPs/CIDRs from sourceNetworks/destinationNetworks .literals.
    """
    key = f"{direction}Networks"
    literals: List[str] = []
    nets = rule.get(key, {})
    for lit in nets.get("literals", []):
        val = lit.get("value")
        if not val:
            continue
        literals.append(val)
    return literals


def _extract_network_object_refs(rule: Dict[str, Any], direction: str) -> List[Dict]:
    """
    Extract network object references (objects list) for source/destination.
    """
    key = f"{direction}Networks"
    refs: List[Dict[str, Any]] = []
    nets = rule.get(key, {})
    for obj in nets.get("objects", []):
        refs.append(obj)
    return refs


def _extract_sgt_objects(rule: Dict[str, Any], direction: str) -> List[Dict[str, Any]]:
    """
    Extract sourceSecurityGroupTags / destinationSecurityGroupTags.
    """
    key = f"{direction}SecurityGroupTags"
    container = rule.get(key, {})
    return container.get("objects", [])


def _extract_realm_users(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract realm User / UserGroup information from rule["users"].
    """
    users_obj = rule.get("users") or {}
    objs = users_obj.get("objects", [])
    realm_users: List[Dict[str, Any]] = []
    realm_groups: List[Dict[str, Any]] = []

    for obj in objs:
        t = obj.get("type")
        if t == "RealmUser":
            realm_users.append(obj)
        elif t == "RealmUserGroup":
            realm_groups.append(obj)

    return {
        "realm_users": realm_users,
        "realm_groups": realm_groups,
    }


def _extract_zones(rule: Dict[str, Any], direction: str) -> List[Dict[str, Any]]:
    """
    Extract sourceZones / destinationZones objects.
    """
    key = f"{direction}Zones"
    container = rule.get(key, {})
    return container.get("objects", [])


def _extract_dynamic_objects(rule: Dict[str, Any], direction: str) -> List[Dict[str, Any]]:
    """
    Extract sourceDynamicObjects / destinationDynamicObjects objects.
    """
    key = f"{direction}DynamicObjects"
    container = rule.get(key, {})
    return container.get("objects", [])


def _extract_applications(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract application objects from rule["applications"]["applications"].
    """
    apps_container = rule.get("applications") or {}
    return apps_container.get("applications", [])


def _extract_urls(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract URL objects and URL categories with reputation.
    """
    urls = rule.get("urls") or {}
    objects = urls.get("objects", [])
    cats = urls.get("urlCategoriesWithReputation", [])
    return {"objects": objects, "categories": cats}


def _extract_ports(rule: Dict[str, Any], direction: str) -> List[Dict[str, Any]]:
    """
    Extract sourcePorts / destinationPorts objects.
    (Note: FMC uses one 'destinationPorts' field in Access Rules,
     but helper kept generic for symmetry.)
    """
    key = f"{direction}Ports"
    container = rule.get(key, {})
    return container.get("objects", [])


def _extract_file_policy(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract filePolicy object, if any.
    """
    return rule.get("filePolicy")


def _extract_ips_policy(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract ipsPolicy object, if any.
    """
    return rule.get("ipsPolicy")


def _basic_rule_summary(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Summarize rule with key attributes plus network-related context.
    """
    meta = rule.get("metadata") or {}
    access_policy = meta.get("accessPolicy") or {}

    sgt_src = _extract_sgt_objects(rule, "source")
    sgt_dst = _extract_sgt_objects(rule, "destination")
    realm_info = _extract_realm_users(rule)
    zones_src = _extract_zones(rule, "source")
    zones_dst = _extract_zones(rule, "destination")
    dyn_src = _extract_dynamic_objects(rule, "source")
    dyn_dst = _extract_dynamic_objects(rule, "destination")
    apps = _extract_applications(rule)
    url_info = _extract_urls(rule)
    dst_ports = _extract_ports(rule, "destination")
    file_policy = _extract_file_policy(rule)
    ips_policy = _extract_ips_policy(rule)

    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "action": rule.get("action"),
        "enabled": rule.get("enabled", True),
        "section": meta.get("section"),
        "category": meta.get("category"),
        "ruleIndex": meta.get("ruleIndex"),
        "accessPolicy": {
            "id": access_policy.get("id"),
            "name": access_policy.get("name"),
        },
        "sendEventsToFMC": rule.get("sendEventsToFMC"),
        "enableSyslog": rule.get("enableSyslog"),
        "logBegin": rule.get("logBegin"),
        "logEnd": rule.get("logEnd"),
        "sgt": {
            "source": sgt_src,
            "destination": sgt_dst,
        },
        "realm": realm_info,
        "zones": {
            "source": zones_src,
            "destination": zones_dst,
        },
        "dynamicObjects": {
            "source": dyn_src,
            "destination": dyn_dst,
        },
        "applications": apps,
        "urls": url_info,
        "destinationPorts": dst_ports,
        "filePolicy": file_policy,
        "ipsPolicy": ips_policy,
        # leave room for network-object match details
        "source_literal_matches": [],
        "destination_literal_matches": [],
        "source_object_matches": [],
        "destination_object_matches": [],
    }


# -----------------------------------------------------------------------------
# Rule search core logic (policy-centric)
# -----------------------------------------------------------------------------

def _match_rule_against_indicator(
    rule: Dict[str, Any],
    indicator: str,
    index: NetworkObjectIndex,
) -> Optional[Dict[str, Any]]:
    """
    Return a rule summary with match details if rule references the indicator
    in source/dest networks (literals or objects). Otherwise None.
    """
    indicator_type = index.classify_indicator(indicator)
    matches_source_literals: List[str] = []
    matches_dest_literals: List[str] = []
    source_object_matches: List[Dict[str, Any]] = []
    dest_object_matches: List[Dict[str, Any]] = []

    # Literal matches
    src_lits = _extract_literal_ips(rule, "source")
    dst_lits = _extract_literal_ips(rule, "destination")

    if indicator_type in ("ip", "network"):
        # IP/CIDR literal matching
        for lit in src_lits:
            try:
                if indicator_type == "ip":
                    ip_obj = ipaddress.ip_address(lit)
                    ip_ind = ipaddress.ip_address(indicator)
                    if ip_obj == ip_ind:
                        matches_source_literals.append(lit)
                else:
                    net_lit = ipaddress.ip_network(lit, strict=False)
                    net_ind = ipaddress.ip_network(indicator, strict=False)
                    if net_lit.overlaps(net_ind):
                        matches_source_literals.append(lit)
            except ValueError:
                continue

        for lit in dst_lits:
            try:
                if indicator_type == "ip":
                    ip_obj = ipaddress.ip_address(lit)
                    ip_ind = ipaddress.ip_address(indicator)
                    if ip_obj == ip_ind:
                        matches_dest_literals.append(lit)
                else:
                    net_lit = ipaddress.ip_network(lit, strict=False)
                    net_ind = ipaddress.ip_network(indicator, strict=False)
                    if net_lit.overlaps(net_ind):
                        matches_dest_literals.append(lit)
            except ValueError:
                continue

    else:
        # FQDN literal? Some deployments might put FQDN in literal "value"
        fqdn_norm = indicator.lower().rstrip(".")
        for lit in src_lits:
            if lit.lower().rstrip(".") == fqdn_norm:
                matches_source_literals.append(lit)
        for lit in dst_lits:
            if lit.lower().rstrip(".") == fqdn_norm:
                matches_dest_literals.append(lit)

    # Object matches
    src_objs = _extract_network_object_refs(rule, "source")
    dst_objs = _extract_network_object_refs(rule, "destination")

    indicator_matches = index.find_matches_for_indicator(indicator)
    # hosts
    host_ids = {h["id"] for h in indicator_matches["matched_hosts"]}
    # networks
    net_ids = {n["id"] for n in indicator_matches["matched_networks"]}
    # ranges
    range_ids = {r["id"] for r in indicator_matches["matched_ranges"]}
    # fqdns
    fqdn_ids = {f["id"] for f in indicator_matches["matched_fqdns"]}
    # groups
    group_ids = {g["id"] for g in indicator_matches["matched_groups"]}
    # dynamic
    dyn_ids = {d["id"] for d in indicator_matches["matched_dynamic_objects"]}

    def _obj_matches(obj: Dict[str, Any]) -> bool:
        oid = obj.get("id")
        if not oid:
            return False
        if oid in host_ids or oid in net_ids or oid in range_ids:
            return True
        if oid in fqdn_ids or oid in group_ids or oid in dyn_ids:
            return True
        return False

    for obj in src_objs:
        if _obj_matches(obj):
            source_object_matches.append(obj)

    for obj in dst_objs:
        if _obj_matches(obj):
            dest_object_matches.append(obj)

    if (
        not matches_source_literals
        and not matches_dest_literals
        and not source_object_matches
        and not dest_object_matches
    ):
        return None

    summary = _basic_rule_summary(rule)
    summary["source_literal_matches"] = matches_source_literals
    summary["destination_literal_matches"] = matches_dest_literals
    summary["source_object_matches"] = source_object_matches
    summary["destination_object_matches"] = dest_object_matches

    return summary


def _search_rules_in_policy(
    policy_id: str,
    indicator: str,
    domain_uuid: Optional[str],
    client: FMCClient,
) -> Dict[str, Any]:
    """
    Core function to:
      1. Build the network object index once.
      2. Fetch and scan Access Rules in the given policy.
    """

    index = NetworkObjectIndex.build_from_fmc(client, domain_uuid=domain_uuid)
    rules = client.list_access_rules_for_policy(policy_id, domain_uuid=domain_uuid)

    matched_rules: List[Dict[str, Any]] = []
    for rule in rules:
        matched = _match_rule_against_indicator(rule, indicator, index)
        if matched:
            matched_rules.append(matched)

    indicator_matches = index.find_matches_for_indicator(indicator)

    return {
        "fmc_base_url": client.base_url,
        "domain_uuid": client.get_effective_domain_uuid(domain_uuid),
        "access_policy_id": policy_id,
        "query": indicator,
        "query_kind": indicator_matches["indicator_type"],
        "matched_object_count": sum(
            len(indicator_matches[k])
            for k in [
                "matched_hosts",
                "matched_networks",
                "matched_ranges",
                "matched_fqdns",
                "matched_groups",
                "matched_dynamic_objects",
            ]
        ),
        "object_match_summary": indicator_matches,
        "matched_rule_count": len(matched_rules),
        "matched_rules": matched_rules,
    }


# -----------------------------------------------------------------------------
# High-level FMC-driven search across Access Policies
# -----------------------------------------------------------------------------

def _validate_indicator_type(indicator: str, indicator_type: str) -> Tuple[bool, Optional[str]]:
    """
    Validate indicator against explicit indicator_type.
    """
    try:
        if indicator_type == "ip":
            ipaddress.ip_address(indicator)
            return True, None
        if indicator_type == "subnet":
            ipaddress.ip_network(indicator, strict=False)
            return True, None
        if indicator_type == "fqdn":
            # Very loose check: must contain at least one dot and not be numeric-only
            s = indicator.strip()
            if "." not in s or s.replace(".", "").isdigit():
                return False, "Value does not look like an FQDN"
            return True, None
        if indicator_type == "auto":
            return True, None
    except ValueError as e:
        return False, f"Invalid {indicator_type}: {e}"
    return False, f"Unsupported indicator_type: {indicator_type}"


def _normalize_indicator_auto(indicator: str) -> Tuple[str, str, Optional[str]]:
    """
    When indicator_type="auto", try to classify IP, subnet, or FQDN.
    """
    # IP?
    try:
        ipaddress.ip_address(indicator)
        return indicator, "ip", None
    except ValueError:
        pass

    # CIDR?
    try:
        ipaddress.ip_network(indicator, strict=False)
        return indicator, "subnet", None
    except ValueError:
        pass

    # FQDN fallback
    s = indicator.strip()
    if "." in s and not s.replace(".", "").isdigit():
        return s, "fqdn", None

    return indicator, "fqdn", "Could not classify indicator cleanly; treating as FQDN"


def _search_access_policies_for_indicator(
    client: FMCClient,
    indicator: str,
    indicator_type: str,
    scope: str,
    policy_name: Optional[str],
    max_results: int,
    domain_uuid: Optional[str],
) -> Dict[str, Any]:
    """
    FMC-centric search: list Access Policies, build index once per query,
    and scan rules across policies.
    """

    # 1) Validate / normalise indicator
    if indicator_type == "auto":
        indicator, indicator_type, warn = _normalize_indicator_auto(indicator)
        if warn:
            logger.info("Indicator auto-classification warning: %s", warn)
    else:
        ok, err = _validate_indicator_type(indicator, indicator_type)
        if not ok:
            return {"error": {"category": "VALIDATION", "message": err}}

    # 2) Fetch policies based on scope
    all_policies = client.list_access_policies(domain_uuid=domain_uuid)
    if scope == "policy":
        if not policy_name:
            return {
                "error": {
                    "category": "VALIDATION",
                    "message": "scope='policy' requires 'policy_name'",
                }
            }
        # Match by name (case-sensitive for now)
        policies = [p for p in all_policies if p.get("name") == policy_name]
        if not policies:
            return {
                "error": {
                    "category": "NOT_FOUND",
                    "message": f"No Access Policy named '{policy_name}' found.",
                }
            }
    else:
        # scope = "fmc"
        policies = all_policies

    # 3) Build index once
    index = NetworkObjectIndex.build_from_fmc(client, domain_uuid=domain_uuid)

    # 4) Scan rules in each policy, stop when max_results reached
    matched_rules: List[Dict[str, Any]] = []
    policies_scanned: List[Dict[str, Any]] = []
    truncated = False

    for p in policies:
        if len(matched_rules) >= max_results:
            truncated = True
            break

        pid = p.get("id")
        pname = p.get("name")
        if not pid:
            continue

        policies_scanned.append({"id": pid, "name": pname})
        rules = client.list_access_rules_for_policy(pid, domain_uuid=domain_uuid)

        for rule in rules:
            if len(matched_rules) >= max_results:
                truncated = True
                break
            matched = _match_rule_against_indicator(rule, indicator, index)
            if matched:
                matched_rules.append(matched)

    indicator_matches = index.find_matches_for_indicator(indicator)

    return {
        "meta": {
            "fmc": {
                "base_url": client.base_url,
                "domain_uuid": client.get_effective_domain_uuid(domain_uuid),
            },
            "indicator": indicator,
            "indicator_type": indicator_type,
            "matched_object_count": sum(
                len(indicator_matches[k])
                for k in [
                    "matched_hosts",
                    "matched_networks",
                    "matched_ranges",
                    "matched_fqdns",
                    "matched_groups",
                    "matched_dynamic_objects",
                ]
            ),
            "matched_rules_count": len(matched_rules),
            "policies_scanned": len(policies_scanned),
            "scope": scope,
            "truncated": truncated,
        },
        "items": matched_rules,
        "objects": indicator_matches,
        "policies_scanned": policies_scanned,
    }


# -----------------------------------------------------------------------------
# Device / target resolution helper
# -----------------------------------------------------------------------------

def _resolve_target_to_policy(
    client: FMCClient,
    target: str,
    domain_uuid: Optional[str],
) -> Dict[str, Any]:
    """
    Resolve a target name to its Access Policy.

    Target can match:
      - Device name
      - Device hostName
      - HA pair name
      - Cluster name
    """
    devices = client.list_devices(domain_uuid=domain_uuid)
    ha_pairs = client.list_device_ha_pairs(domain_uuid=domain_uuid)
    clusters = client.list_device_clusters(domain_uuid=domain_uuid)

    # 1) Direct device match
    for d in devices:
        if d.get("name") == target or d.get("hostName") == target:
            acp = d.get("accessPolicy")
            return {
                "target_type": "DEVICE",
                "target_id": d.get("id"),
                "target_name": d.get("name"),
                "access_policy": acp,
            }

    # 2) HA pair match
    for ha in ha_pairs:
        if ha.get("name") == target:
            # Usually there is a 'primary' device id that has the ACP
            members = ha.get("devices", [])
            acp = None
            dev_id = None
            for m in members:
                dev_id = m.get("id")
                if dev_id:
                    detail = client.get_device(dev_id, domain_uuid=domain_uuid)
                    acp = detail.get("accessPolicy")
                    if acp:
                        break
            return {
                "target_type": "HA",
                "target_id": ha.get("id"),
                "target_name": ha.get("name"),
                "access_policy": acp,
            }

    # 3) Cluster match
    for cl in clusters:
        if cl.get("name") == target:
            members = cl.get("devices", [])
            acp = None
            dev_id = None
            for m in members:
                dev_id = m.get("id")
                if dev_id:
                    detail = client.get_device(dev_id, domain_uuid=domain_uuid)
                    acp = detail.get("accessPolicy")
                    if acp:
                        break
            return {
                "target_type": "CLUSTER",
                "target_id": cl.get("id"),
                "target_name": cl.get("name"),
                "access_policy": acp,
            }

    return {
        "target_type": "UNKNOWN",
        "target_id": None,
        "target_name": target,
        "access_policy": None,
    }


# -----------------------------------------------------------------------------
# FastMCP server & tools
# -----------------------------------------------------------------------------

mcp = FastMCP("cisco-secure-firewall-mcp")


@mcp.tool()
def find_rules_by_ip_or_fqdn(
    query: str,
    access_policy_id: str,
    domain_uuid: Optional[str] = None,
) -> str:
    """
    Find FMC Access Control rules in a given policy that reference a specific IP, CIDR, or FQDN.

    Matching logic:
      1. Build a NetworkObjectIndex from FMC objects:
         - Hosts (/object/hosts)
         - Networks (/object/networks)
         - Ranges (/object/ranges)
         - FQDN objects (/object/fqdns, if available)
         - Network groups (/object/networkgroups)
         - Dynamic objects (/object/dynamicobjects, where available)
      2. Scan Access Control rules in the specified Access Policy:
         - sourceNetworks.literals / destinationNetworks.literals
         - sourceNetworks.objects / destinationNetworks.objects
      3. Return a JSON summary containing:
         - matched FMC network/FQDN objects
         - rules that reference them (or literals matching the query)

    Args:
        query:
            - Single IP address, e.g. "10.10.10.5"
            - CIDR network, e.g. "10.10.10.0/24"
            - FQDN string, e.g. "example.com"
        access_policy_id:
            The UUID of the Access Policy to search.
        domain_uuid:
            Optional FMC domain UUID; if omitted, the client will derive it
            via /api/fmc_platform/v1/info/domain (suitable for single-domain
            or Global domain scenarios).

    Returns:
        JSON string with either:

        - On success:
            {
              "fmc_base_url": "...",
              "domain_uuid": "...",
              "access_policy_id": "...",
              "query": "...",
              "query_kind": "ip" | "network" | "fqdn",
              "matched_object_count": N,
              "object_match_summary": [...],
              "matched_rule_count": M,
              "matched_rules": [
                {
                  "id": "...",
                  "name": "...",
                  "action": "...",
                  "enabled": true,
                  "hit_count": 123,
                  "source_literal_matches": [...],
                  "destination_literal_matches": [...],
                  "source_object_matches": [...],
                  "destination_object_matches": [...]
                },
                ...
              ]
            }

        - On error:
            {
              "error": {
                "category": "FMC_CLIENT" | "UNEXPECTED",
                "message": "..."
              }
            }
    """
    logger.info(
        "Tool find_rules_by_ip_or_fqdn called: query=%s, policy=%s, domain=%s",
        query,
        access_policy_id,
        domain_uuid,
    )

    try:
        result = _search_rules_in_policy(
            access_policy_id,
            query,
            domain_uuid,
            fmc_client,
        )
        return json.dumps(result)
    except FMCClientError as e:
        logger.exception("FMC client error in find_rules_by_ip_or_fqdn")
        return json.dumps(
            {
                "error": {
                    "category": "FMC_CLIENT",
                    "message": str(e),
                }
            }
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Unexpected error in find_rules_by_ip_or_fqdn")
        return json.dumps(
            {
                "error": {
                    "category": "UNEXPECTED",
                    "message": str(e),
                }
            }
        )


@mcp.tool()
def find_rules_for_target(
    query: str,
    target: str,
    domain_uuid: Optional[str] = None,
) -> str:
    """
    High-level helper: resolve an FMC device/FTD target (device, HA pair, or cluster)
    to its Access Policy and then find rules that reference an IP/CIDR/FQDN.

    This is what the AI Agent will typically call.

    Args:
        query:
            IPv4/IPv6 address (e.g. "10.10.10.5"),
            CIDR network (e.g. "10.10.10.0/24"), or
            FQDN (e.g. "example.com").
        target:
            A string identifying a device/HA/cluster, matched against:
              - device.name
              - device.hostName
              - HA pair name
              - cluster name
        domain_uuid:
            Optional FMC domain UUID override.

    Returns:
        JSON string with rule matches and resolution details, or an "error" object.
    """
    logger.info(
        "Tool find_rules_for_target called: query=%s, target=%s, domain=%s",
        query,
        target,
        domain_uuid,
    )
    try:
        resolution = _resolve_target_to_policy(
            fmc_client,
            target,
            domain_uuid,
        )
        acp = resolution.get("access_policy")
        if not acp or not acp.get("id"):
            return json.dumps(
                {
                    "resolution": resolution,
                    "error": {
                        "category": "NOT_FOUND",
                        "message": "No Access Policy associated with target.",
                    },
                }
            )

        policy_id = acp["id"]
        search_result = _search_rules_in_policy(
            policy_id,
            query,
            domain_uuid,
            fmc_client,
        )
        return json.dumps(
            {
                "resolution": resolution,
                "search_result": search_result,
            }
        )
    except FMCClientError as e:
        logger.exception("FMC client error in find_rules_for_target")
        return json.dumps(
            {
                "error": {
                    "category": "FMC_CLIENT",
                    "message": str(e),
                }
            }
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Unexpected error in find_rules_for_target")
        return json.dumps(
            {
                "error": {
                    "category": "UNEXPECTED",
                    "message": str(e),
                }
            }
        )


@mcp.tool()
def search_access_rules(
    indicator: str,
    indicator_type: str = "auto",
    scope: str = "fmc",
    policy_name: Optional[str] = None,
    max_results: int = 100,
    domain_uuid: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FMC-driven rule search for an IP/CIDR/FQDN across Access Policies.

    This tool is FMC-centric and does *not* require an FTD/cluster name. It will:

      1. Validate and classify the ``indicator`` as IP, CIDR, or FQDN.
      2. List Access Policies on the configured FMC/domain.
      3. Build the FMC network object index **once** for the whole query.
      4. Depending on ``scope``:
         - "policy": search only the policy whose name matches ``policy_name``.
         - "fmc"   : search all Access Policies on this FMC (up to ``max_results``).
      5. For each matching rule, return:
         - basic rule metadata (id, name, action, enabled, section, hit count)
         - which literals/objects matched in source/destination

    Args:
        indicator:
            IP address ("10.10.10.5"), CIDR ("10.10.10.0/24"), or FQDN ("example.com").
        indicator_type:
            Optional hint to restrict the expected type:
              - "auto"   : infer from value (default)
              - "ip"     : require single IP address
              - "subnet" : require CIDR network
              - "fqdn"   : require FQDN
        scope:
            - "policy": search a single Access Policy (requires ``policy_name``).
            - "fmc"   : search all Access Policies on this FMC.
        policy_name:
            Access Policy name when ``scope="policy"``.
        max_results:
            Hard cap on number of matching rules returned (1–500).
        domain_uuid:
            Optional override of FMC domain UUID. If omitted, the client will
            auto-discover the domain (suitable for single-domain deployments).

    Returns:
        A JSON-serialisable dict with ``meta`` and ``items`` keys, or an
        ``error`` object if validation or FMC access fails.
    """
    logger.info(
        "Tool search_access_rules called: indicator=%s, indicator_type=%s, "
        "scope=%s, policy_name=%s, max_results=%s, domain=%s",
        indicator,
        indicator_type,
        scope,
        policy_name,
        max_results,
        domain_uuid,
    )

    if max_results < 1 or max_results > 500:
        return {
            "error": {
                "category": "VALIDATION",
                "message": "max_results must be between 1 and 500",
            }
        }

    try:
        return _search_access_policies_for_indicator(
            fmc_client,
            indicator,
            indicator_type,
            scope,
            policy_name,
            max_results,
            domain_uuid,
        )
    except FMCClientError as e:
        logger.exception("FMC client error in search_access_rules")
        return {
            "error": {
                "category": "FMC_CLIENT",
                "message": str(e),
            }
        }
    except Exception as e:  # noqa: BLE001
        logger.exception("Unexpected error in search_access_rules")
        return {
            "error": {
                "category": "UNEXPECTED",
                "message": str(e),
            }
        }


# -----------------------------------------------------------------------------
# Main entrypoint
# -----------------------------------------------------------------------------
def main() -> None:
    """Entry point for running the MCP server.

    By default this runs the HTTP transport for use in Docker / remote agents.
    Set MCP_TRANSPORT=stdio to use stdio instead (for desktop MCP clients).
    """
    logger.info("Starting Cisco Secure Firewall FMC MCP server")
    logger.info("FMC_BASE_URL=%s", FMC_BASE_URL)
    logger.info("FMC_VERIFY_SSL=%s", FMC_VERIFY_SSL)
    logger.info("FMC_TIMEOUT=%s", FMC_TIMEOUT)
    logger.info("FMC_DOMAIN_UUID=%s", FMC_DOMAIN_UUID)

    transport = os.getenv("MCP_TRANSPORT", "http").lower()

    if transport == "http":
        host = os.getenv("MCP_HTTP_HOST", "0.0.0.0")
        port_str = os.getenv("MCP_HTTP_PORT", "8000")
        try:
            port = int(port_str)
        except ValueError:
            logger.warning("Invalid MCP_HTTP_PORT=%s, falling back to 8000", port_str)
            port = 8000
        path = os.getenv("MCP_HTTP_PATH", "/mcp")
        logger.info("Starting FastMCP HTTP server on %s:%s%s", host, port, path)
        mcp.run(transport="http", host=host, port=port, path=path)
    else:
        logger.info("Starting FastMCP stdio server (MCP_TRANSPORT=%s)", transport)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
