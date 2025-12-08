from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from fastmcp import FastMCP  # FastMCP 2.x

# --------------------------------------------------------------------------------------
# Logging (STDERR only – safe for MCP servers)
# --------------------------------------------------------------------------------------

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("sfw-mcp-fmc")

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


@dataclass
class FMCSettings:
    """
    Strongly-typed FMC configuration, loaded from environment variables.

    Required env vars:
      - FMC_BASE_URL   (e.g. https://10.127.245.140)
      - FMC_USERNAME
      - FMC_PASSWORD

    Optional:
      - FMC_VERIFY_SSL (true/false, default: false)
      - FMC_TIMEOUT    (seconds, default: 30)
      - FMC_DOMAIN_UUID (optional, if you want to pin a specific domain)
    """

    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: float = 30.0
    domain_uuid: Optional[str] = None

    @classmethod
    def from_env(cls) -> "FMCSettings":
        base_url = os.getenv("FMC_BASE_URL")
        username = os.getenv("FMC_USERNAME")
        password = os.getenv("FMC_PASSWORD")

        if not base_url or not username or not password:
            raise RuntimeError(
                "FMC_BASE_URL, FMC_USERNAME, and FMC_PASSWORD must be set "
                "as environment variables."
            )

        verify_str = os.getenv("FMC_VERIFY_SSL", "false").strip().lower()
        verify_ssl = verify_str in {"1", "true", "yes", "on"}

        timeout_str = os.getenv("FMC_TIMEOUT", "30").strip()
        try:
            timeout = float(timeout_str)
        except ValueError:
            timeout = 30.0

        domain_uuid = os.getenv("FMC_DOMAIN_UUID") or None

        return cls(
            base_url=base_url.rstrip("/"),
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            domain_uuid=domain_uuid,
        )


# --------------------------------------------------------------------------------------
# FMC Client (HTTP + Token handling)
# --------------------------------------------------------------------------------------


class FMCClientError(Exception):
    """Base exception for FMC client errors."""


class FMCAuthError(FMCClientError):
    """Authentication / token issues."""


class FMCRequestError(FMCClientError):
    """HTTP/network problems when talking to FMC."""


class FMCClient:
    """
    Minimal async FMC REST API client.

    - Uses POST /api/fmc_platform/v1/auth/generatetoken to obtain tokens.
    - Stores X-auth-access-token and DOMAIN_UUID from response headers.
    """

    def __init__(self, settings: FMCSettings) -> None:
        self._settings = settings
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._domain_uuid: Optional[str] = settings.domain_uuid

    @property
    def settings(self) -> FMCSettings:
        """Expose the settings in a read-only way for helpers."""
        return self._settings

    async def _authenticate(self) -> None:
        """Obtain FMC access + refresh tokens."""
        url = f"{self._settings.base_url}/api/fmc_platform/v1/auth/generatetoken"
        logger.debug("Authenticating to FMC at %s", url)

        try:
            async with httpx.AsyncClient(
                verify=self._settings.verify_ssl, timeout=self._settings.timeout
            ) as client:
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    auth=(self._settings.username, self._settings.password),
                )
        except httpx.RequestError as exc:
            logger.error("FMC auth request failed: %s", exc)
            raise FMCRequestError(f"FMC auth request failed: {exc}") from exc

        # Successful auth returns 204 + tokens in headers (empty body)
        if response.status_code != 204:
            logger.error(
                "FMC auth failed with status %s: %s",
                response.status_code,
                response.text,
            )
            raise FMCAuthError(
                f"FMC auth failed with status {response.status_code}"
            )

        access_token = response.headers.get("X-auth-access-token")
        refresh_token = response.headers.get("X-auth-refresh-token")
        domain_uuid = (
            response.headers.get("DOMAIN_UUID") or response.headers.get("Domain_UUID")
        )

        if not access_token:
            raise FMCAuthError("FMC auth succeeded but no X-auth-access-token header")

        self._access_token = access_token
        self._refresh_token = refresh_token
        if domain_uuid and not self._domain_uuid:
            self._domain_uuid = domain_uuid

        logger.info("FMC authentication successful; domain_uuid=%s", self._domain_uuid)

    async def _ensure_authenticated(self) -> None:
        if not self._access_token:
            await self._authenticate()

    async def ensure_domain_uuid(self) -> str:
        """
        Ensure we have a valid domain UUID.

        Priority:
          1. Explicit domain_uuid in settings
          2. DOMAIN_UUID header from auth
          3. GET /api/fmc_platform/v1/info/domain
        """
        if self._domain_uuid:
            return self._domain_uuid

        await self._ensure_authenticated()
        url = f"{self._settings.base_url}/api/fmc_platform/v1/info/domain"
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": self._access_token or "",
        }

        try:
            async with httpx.AsyncClient(
                verify=self._settings.verify_ssl, timeout=self._settings.timeout
            ) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
        except httpx.RequestError as exc:
            logger.error("Failed to query FMC domain info: %s", exc)
            raise FMCRequestError(f"Failed to query FMC domain info: {exc}") from exc

        data = response.json()
        items = data.get("items") or []
        if not items:
            raise FMCRequestError("FMC returned no domains in /info/domain response")

        self._domain_uuid = items[0].get("uuid")
        if not self._domain_uuid:
            raise FMCRequestError("FMC /info/domain response missing uuid")

        logger.info("Discovered FMC domain_uuid=%s", self._domain_uuid)
        return self._domain_uuid

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        ignore_statuses: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """
        Internal helper for authenticated JSON requests to config API.

        `ignore_statuses` lets some callers (e.g. FQDN/dynamicobjects on
        older FMC) treat a 404 as "feature not available" instead of a hard
        error. In that case we return an empty collection-style payload.
        """
        await self._ensure_authenticated()
        if not self._access_token:
            raise FMCAuthError("No access token, authentication failed")

        url = f"{self._settings.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": self._access_token,
        }

        logger.debug("FMC request %s %s params=%s", method, url, params)

        try:
            async with httpx.AsyncClient(
                verify=self._settings.verify_ssl, timeout=self._settings.timeout
            ) as client:
                response = await client.request(
                    method=method, url=url, headers=headers, params=params
                )
        except httpx.RequestError as exc:
            logger.error("FMC %s %s failed: %s", method, url, exc)
            raise FMCRequestError(f"FMC {method} {url} failed: {exc}") from exc

        # Handle token expiry (basic re-auth and one retry)
        if response.status_code == 401:
            logger.warning("FMC token expired, re-authenticating once")
            self._access_token = None
            await self._authenticate()
            headers["X-auth-access-token"] = self._access_token or ""
            try:
                async with httpx.AsyncClient(
                    verify=self._settings.verify_ssl, timeout=self._settings.timeout
                ) as client:
                    response = await client.request(
                        method=method, url=url, headers=headers, params=params
                    )
            except httpx.RequestError as exc:
                logger.error("FMC retry %s %s failed: %s", method, url, exc)
                raise FMCRequestError(
                    f"FMC retry {method} {url} failed: {exc}"
                ) from exc

        if ignore_statuses and response.status_code in ignore_statuses:
            logger.warning(
                "FMC request %s %s returned status %s (ignored); treating as empty.",
                method,
                url,
                response.status_code,
            )
            # Return an empty "collection" payload to keep callers simple.
            limit_val = 0
            if params:
                try:
                    limit_val = int(params.get("limit", 0))
                except (TypeError, ValueError):
                    limit_val = 0
            return {
                "items": [],
                "paging": {"offset": 0, "limit": limit_val, "count": 0, "pages": 0},
            }

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "FMC request failed: status=%s body=%s",
                response.status_code,
                response.text,
            )
            raise FMCRequestError(
                f"FMC request failed with status {response.status_code}"
            ) from exc

        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError:
            logger.error("FMC returned non-JSON body: %s", response.text[:512])
            raise FMCRequestError("FMC returned non-JSON response")

    # ---- Generic pagination helper ----------------------------------------------------

    async def _list_paginated(
        self,
        path_suffix: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        limit: int = 1000,
        hard_page_limit: int = 20,
        expanded: bool = False,
        ignore_statuses: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generic 'list with paging' helper for FMC config endpoints.
        Supports:
          - limit/offset pagination
          - optional expanded=true
          - optional ignore_statuses (e.g. 404 on older FMC)
        """
        domain_uuid = await self.ensure_domain_uuid()
        path = f"/api/fmc_config/v1/domain/{domain_uuid}{path_suffix}"

        all_items: List[Dict[str, Any]] = []
        offset = 0
        page_count = 0

        base_params = params.copy() if params else {}
        base_params.setdefault("limit", limit)
        if expanded:
            base_params.setdefault("expanded", "true")

        while True:
            query_params = base_params.copy()
            query_params["offset"] = offset

            data = await self._request(
                "GET",
                path,
                params=query_params,
                ignore_statuses=ignore_statuses,
            )
            items = data.get("items") or []
            all_items.extend(items)

            paging = data.get("paging") or {}
            next_link = paging.get("next")
            page_count += 1

            if not next_link or page_count >= hard_page_limit:
                break

            offset += limit

        logger.info(
            "Fetched %d items from %s (pages=%d)",
            len(all_items),
            path_suffix,
            page_count,
        )
        return all_items

    # ---- Access rules -----------------------------------------------------------------

    async def list_access_rules(
        self,
        access_policy_id: str,
        *,
        limit: int = 1000,
        hard_page_limit: int = 10,
        expanded: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve access control rules for a given Access Policy.

        Uses:
          GET /api/fmc_config/v1/domain/{domain_UUID}/policy/accesspolicies/{policy_UUID}/accessrules
          with limit/offset + paging.next pagination.
        """
        params: Dict[str, Any] = {}
        if expanded:
            params["expanded"] = "true"

        path_suffix = f"/policy/accesspolicies/{access_policy_id}/accessrules"

        return await self._list_paginated(
            path_suffix,
            params=params,
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=False,  # expanded already set in params
        )

    # ---- Network / host / FQDN / range / group / dynamic objects ----------------------

    async def list_host_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/object/hosts",
            expanded=True,
        )

    async def list_network_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/object/networks",
            expanded=True,
        )

    async def list_range_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/object/ranges",
            expanded=True,
        )

    async def list_fqdn_objects(self) -> List[Dict[str, Any]]:
        """
        FQDN objects: /object/fqdns

        On some older FMC versions or feature sets this endpoint might not
        exist, so we treat 404 as "no FQDN support" instead of failing the
        whole query.
        """
        return await self._list_paginated(
            "/object/fqdns",
            expanded=True,
            ignore_statuses={404},
        )

    async def list_network_group_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/object/networkgroups",
            expanded=True,
        )

    async def list_dynamic_objects(self) -> List[Dict[str, Any]]:
        """
        Dynamic Objects: /object/dynamicobjects

        On older FMCs this may not exist, so we ignore 404 similarly to FQDNs.
        """
        return await self._list_paginated(
            "/object/dynamicobjects",
            expanded=True,
            ignore_statuses={404},
            hard_page_limit=5,
        )

    # ---- Devices / HA / Clusters ------------------------------------------------------

    async def list_device_records(self) -> List[Dict[str, Any]]:
        """
        List individual device records (physical FTDs, etc.).
        """
        return await self._list_paginated(
            "/devices/devicerecords",
            expanded=True,
            hard_page_limit=5,
        )

    async def list_device_ha_pairs(self) -> List[Dict[str, Any]]:
        """
        List FTD HA pairs under /devicehapairs/ftddevicehapairs.
        """
        return await self._list_paginated(
            "/devicehapairs/ftddevicehapairs",
            expanded=True,
            hard_page_limit=5,
            ignore_statuses={404},  # if HA feature not present
        )

    async def list_device_clusters(self) -> List[Dict[str, Any]]:
        """
        List clustered devices (path may vary slightly by FMC version).
        """
        return await self._list_paginated(
            "/deviceclusters/clusters",
            expanded=True,
            hard_page_limit=5,
            ignore_statuses={404},  # if clustering not present
        )

    # ---- Policy assignments -----------------------------------------------------------

    async def list_policy_assignments(self) -> List[Dict[str, Any]]:
        """
        List policy assignments (AccessPolicy, FTDNatPolicy, Platform, Health, etc.)
        and their targets (Device, DeviceHAPair, DeviceCluster, ...).

        We use this especially to resolve AccessPolicy for HA pairs / clusters.
        """
        return await self._list_paginated(
            "/assignment/policyassignments",
            expanded=True,
            hard_page_limit=5,
        )


# --------------------------------------------------------------------------------------
# IP / FQDN matching helpers
# --------------------------------------------------------------------------------------


class QueryKind:
    IP = "ip"
    NETWORK = "network"
    FQDN = "fqdn"
    RAW = "raw"


def parse_query(query: str) -> Tuple[str, Any]:
    """
    Parse the user query into IP / network / fqdn.

    Returns:
      (kind, value)
    """
    q = query.strip()

    # Try IP or network
    try:
        if "/" in q:
            net = ipaddress.ip_network(q, strict=False)
            return (QueryKind.NETWORK, net)
        else:
            ip = ipaddress.ip_address(q)
            return (QueryKind.IP, ip)
    except ValueError:
        # Not an IP, treat as FQDN-ish string
        return (QueryKind.FQDN, q.lower())


def parse_literal_value(value: str) -> Tuple[str, Any]:
    """
    Interpret a literal's 'value' field in FMC rule (IP, CIDR, FQDN, etc.).
    """
    v = value.strip()
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            return (QueryKind.NETWORK, net)
        else:
            ip = ipaddress.ip_address(v)
            return (QueryKind.IP, ip)
    except ValueError:
        return (QueryKind.FQDN, v.lower())


def literal_matches(query_kind: str, query_value: Any, literal: Dict[str, Any]) -> bool:
    """
    Check whether a rule literal matches the query.

    This implementation only considers 'value' from literals under:
      - sourceNetworks.literals
      - destinationNetworks.literals
    """
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
        # Exact match for now; we can extend to suffix/contains later
        return raw_value.lower() == query_value

    # Fallback: simple substring
    return query_value in raw_value


def collect_matching_literals(
    query_kind: str, query_value: Any, network_block: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Given a sourceNetworks/destinationNetworks block, return literals that match.
    """
    if not network_block:
        return []

    literals = network_block.get("literals") or []
    matches: List[Dict[str, Any]] = []

    for lit in literals:
        try:
            if literal_matches(query_kind, query_value, lit):
                matches.append(lit)
        except Exception as exc:  # defensive guardrail
            logger.debug("Error matching literal %s: %s", lit, exc)

    return matches


# --------------------------------------------------------------------------------------
# Network object index (hosts, networks, ranges, FQDNs, groups, dynamic)
# --------------------------------------------------------------------------------------


@dataclass
class AddressInterval:
    """
    Represents a contiguous IP space [start, end] for either IPv4 or IPv6.
    """
    version: int  # 4 or 6
    start: int
    end: int


@dataclass
class NetworkObject:
    id: str
    name: str
    type: str  # Host, Network, Range, FQDN, NetworkGroup, DynamicObject, etc.
    intervals: List[AddressInterval] = field(default_factory=list)
    fqdns: List[str] = field(default_factory=list)
    member_ids: List[str] = field(default_factory=list)  # for groups/dynamic


class NetworkObjectIndex:
    """
    Index of FMC network-related objects with matching helpers.

    - Hosts → single IP
    - Networks → CIDR (interval)
    - Ranges → start-end interval
    - FQDN objects → fqdn strings
    - NetworkGroups → can have objects + literals
    - DynamicObjects → treated similarly (if FMC exposes literals)
    """

    def __init__(self) -> None:
        self.by_id: Dict[str, NetworkObject] = {}

    # ---- Construction ---------------------------------------------------------------

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
            # Safety: do not mix v4/v6
            raise ValueError("IP range has mixed versions")
        s = int(start_ip)
        e = int(end_ip)
        if e < s:
            s, e = e, s
        return AddressInterval(version=start_ip.version, start=s, end=e)

    def add_host(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        value = obj.get("value")
        if not obj_id or not value:
            return

        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            logger.debug("Host object '%s' has non-IP value '%s'", name, value)
            return

        interval = self._ip_to_interval(ip)
        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="Host",
            intervals=[interval],
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
            logger.debug("Network object '%s' has invalid value '%s'", name, value)
            return

        interval = self._network_to_interval(net)
        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="Network",
            intervals=[interval],
        )

    def add_range(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        value = obj.get("value")
        if not obj_id or not value:
            return

        # Expect something like "10.0.0.1-10.0.0.10"
        parts = str(value).split("-")
        if len(parts) != 2:
            logger.debug("Range object '%s' has invalid value '%s'", name, value)
            return

        try:
            start_ip = ipaddress.ip_address(parts[0].strip())
            end_ip = ipaddress.ip_address(parts[1].strip())
            interval = self._range_to_interval(start_ip, end_ip)
        except ValueError:
            logger.debug("Range object '%s' has invalid IPs '%s'", name, value)
            return

        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="Range",
            intervals=[interval],
        )

    def add_fqdn(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        value = obj.get("value")
        if not obj_id or not value:
            return

        fqdn = str(value).lower()
        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="FQDN",
            fqdns=[fqdn],
        )

    def _add_literals_to_object(
        self, netobj: NetworkObject, literals: List[Dict[str, Any]]
    ) -> None:
        """
        For network groups / dynamic objects we may have literals inside the object.
        """
        for lit in literals:
            v = lit.get("value")
            if not v:
                continue

            kind, parsed = parse_literal_value(str(v))
            try:
                if kind == QueryKind.IP:
                    interval = self._ip_to_interval(parsed)
                    netobj.intervals.append(interval)
                elif kind == QueryKind.NETWORK:
                    interval = self._network_to_interval(parsed)
                    netobj.intervals.append(interval)
                elif kind == QueryKind.FQDN:
                    netobj.fqdns.append(str(parsed).lower())
            except Exception as exc:
                logger.debug("Error adding literal '%s' to %s: %s", v, netobj.id, exc)

    def add_network_group(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        if not obj_id:
            return

        netobj = NetworkObject(
            id=obj_id,
            name=name,
            type="NetworkGroup",
            intervals=[],
            fqdns=[],
            member_ids=[],
        )

        # child objects (other network/host/range/fqdn/group/dynamic)
        for child in obj.get("objects") or []:
            child_id = child.get("id")
            if child_id:
                netobj.member_ids.append(child_id)

        # direct literals
        self._add_literals_to_object(netobj, obj.get("literals") or [])

        self.by_id[obj_id] = netobj

    def add_dynamic_object(self, obj: Dict[str, Any]) -> None:
        """
        Basic support for Dynamic Objects.

        FMC usually exposes mappings via a separate /dynamicobjects/{id}/mappings
        endpoint; but some deployments also show literals directly, so we
        leverage literals if present (safe no-op otherwise).
        """
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        if not obj_id:
            return

        netobj = NetworkObject(
            id=obj_id,
            name=name,
            type="DynamicObject",
            intervals=[],
            fqdns=[],
            member_ids=[],
        )

        self._add_literals_to_object(netobj, obj.get("literals") or [])

        self.by_id[obj_id] = netobj

    # ---- Matching helpers ------------------------------------------------------------

    @staticmethod
    def _intervals_overlap(a: AddressInterval, b: AddressInterval) -> bool:
        if a.version != b.version:
            return False
        return not (a.end < b.start or b.end < a.start)

    def _build_query_intervals(
        self, query_kind: str, query_value: Any
    ) -> List[AddressInterval]:
        """
        Convert query IP / network to intervals (for comparision with ranges / nets).
        """
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
        *,
        visited: Optional[Set[str]] = None,
    ) -> bool:
        """
        Does this object (or its members, for groups/dynamic) match the query?
        """
        if visited is None:
            visited = set()
        if netobj.id in visited:
            return False
        visited.add(netobj.id)

        # 1) Direct IP / network / range intervals
        if query_kind in {QueryKind.IP, QueryKind.NETWORK} and query_intervals:
            for obj_interval in netobj.intervals:
                for q_interval in query_intervals:
                    if self._intervals_overlap(obj_interval, q_interval):
                        return True

        # 2) Direct FQDN
        if query_kind == QueryKind.FQDN:
            q_fqdn = str(query_value).lower()
            if any(fqdn == q_fqdn for fqdn in netobj.fqdns):
                return True

        # 3) Recurse into member_ids (for NetworkGroup / Dynamic that reference others)
        if netobj.member_ids:
            for child_id in netobj.member_ids:
                child = self.by_id.get(child_id)
                if not child:
                    continue
                if self._object_matches(
                    child,
                    query_kind,
                    query_value,
                    query_intervals,
                    visited=visited,
                ):
                    return True

        return False

    def find_matching_objects(
        self, query_kind: str, query_value: Any
    ) -> List[Dict[str, Any]]:
        """
        Return a list of objects (as simple dicts) that match the query.
        """
        query_intervals = self._build_query_intervals(query_kind, query_value)
        results: List[Dict[str, Any]] = []

        for obj in self.by_id.values():
            try:
                if self._object_matches(obj, query_kind, query_value, query_intervals):
                    results.append(
                        {
                            "id": obj.id,
                            "name": obj.name,
                            "type": obj.type,
                            "fqdns": obj.fqdns,
                        }
                    )
            except Exception as exc:
                logger.debug("Error matching object %s: %s", obj.id, exc)

        return results


# --------------------------------------------------------------------------------------
# Shared search helper
# --------------------------------------------------------------------------------------


async def _search_rules_for_query(
    client: FMCClient,
    query: str,
    access_policy_id: str,
) -> Dict[str, Any]:
    """
    Core logic shared by both MCP tools:

      - build object index
      - find matching objects
      - fetch rules (expanded=true)
      - find literal & object matches

    Returns a dict (not JSON string).
    """
    resolved_domain = await client.ensure_domain_uuid()
    settings = client.settings

    query_kind, query_value = parse_query(query)

    # 1) Build network object index
    obj_index = NetworkObjectIndex()

    logger.info("Loading FMC network objects for matching...")

    hosts = await client.list_host_objects()
    for obj in hosts:
        obj_index.add_host(obj)

    networks = await client.list_network_objects()
    for obj in networks:
        obj_index.add_network(obj)

    ranges = await client.list_range_objects()
    for obj in ranges:
        obj_index.add_range(obj)

    fqdnobjs = await client.list_fqdn_objects()
    for obj in fqdnobjs:
        obj_index.add_fqdn(obj)

    groups = await client.list_network_group_objects()
    for obj in groups:
        obj_index.add_network_group(obj)

    dynamic_objs = await client.list_dynamic_objects()
    for obj in dynamic_objs:
        obj_index.add_dynamic_object(obj)

    # 2) Determine which objects match the query
    matching_objects = obj_index.find_matching_objects(query_kind, query_value)
    matched_object_ids = {o["id"]: o for o in matching_objects}

    logger.info(
        "Found %d matching FMC objects for query '%s'",
        len(matching_objects),
        query,
    )

    # 3) Fetch rules with expanded=true so we can see object references
    rules = await client.list_access_rules(
        access_policy_id,
        expanded=True,
    )

    matched_rules: List[Dict[str, Any]] = []

    for rule in rules:
        src_block = rule.get("sourceNetworks") or {}
        dst_block = rule.get("destinationNetworks") or {}

        # Literal matches
        src_lit_matches = collect_matching_literals(
            query_kind, query_value, src_block
        )
        dst_lit_matches = collect_matching_literals(
            query_kind, query_value, dst_block
        )

        # Object matches (by id)
        src_object_matches: List[Dict[str, Any]] = []
        dst_object_matches: List[Dict[str, Any]] = []

        for ref in src_block.get("objects") or []:
            obj_id = ref.get("id")
            if not obj_id:
                continue
            match = matched_object_ids.get(obj_id)
            if match:
                enriched = {
                    **match,
                    "ref_name": ref.get("name"),
                    "ref_type": ref.get("type"),
                }
                src_object_matches.append(enriched)

        for ref in dst_block.get("objects") or []:
            obj_id = ref.get("id")
            if not obj_id:
                continue
            match = matched_object_ids.get(obj_id)
            if match:
                enriched = {
                    **match,
                    "ref_name": ref.get("name"),
                    "ref_type": ref.get("type"),
                }
                dst_object_matches.append(enriched)

        if (
            not src_lit_matches
            and not dst_lit_matches
            and not src_object_matches
            and not dst_object_matches
        ):
            continue

        matched_rules.append(
            {
                "id": rule.get("id"),
                "name": rule.get("name"),
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

    result: Dict[str, Any] = {
        "fmc_base_url": settings.base_url,
        "domain_uuid": resolved_domain,
        "access_policy_id": access_policy_id,
        "query": query,
        "query_kind": query_kind,
        "matched_object_count": len(matching_objects),
        "object_match_summary": matching_objects,
        "matched_rule_count": len(matched_rules),
        "matched_rules": matched_rules,
    }
    return result


# --------------------------------------------------------------------------------------
# MCP server + tools
# --------------------------------------------------------------------------------------

mcp = FastMCP("cisco-secure-firewall-fmc")  # MCP server name


@mcp.tool()
async def find_rules_by_ip_or_fqdn(
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
         - Dynamic objects (/object/dynamicobjects, best-effort)
      2. Determine which objects match the query.
      3. Fetch access rules (expanded=true) and find:
         - literal matches in source/destinationNetworks.literals
         - object matches in source/destinationNetworks.objects
           (by object id, including group/dynamic objects that contain matching members)
    """
    try:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid

        client = FMCClient(settings)

        result = await _search_rules_for_query(client, query, access_policy_id)
        return json.dumps(result, indent=2)

    except FMCClientError as fmc_err:
        logger.error("FMCClientError in find_rules_by_ip_or_fqdn: %s", fmc_err)
        error_payload = {
            "error": {
                "category": "FMC_CLIENT",
                "message": str(fmc_err),
            }
        }
        return json.dumps(error_payload, indent=2)

    except Exception as exc:
        logger.exception("Unexpected error in find_rules_by_ip_or_fqdn")
        error_payload = {
            "error": {
                "category": "UNEXPECTED",
                "message": str(exc),
            }
        }
        return json.dumps(error_payload, indent=2)


@mcp.tool()
async def find_rules_for_target(
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
            Device identifier, e.g. FTD HA/cluster name ("FTD-DC"),
            standalone FTD name ("FTD-1"), or management FQDN.
        domain_uuid:
            Optional FMC domain UUID override.

    Returns:
        JSON string with:
          - target / resolved_device (kind=device|ha|cluster)
          - access_policy_id and policy name
          - same rule match payload as find_rules_by_ip_or_fqdn
    """
    try:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid

        client = FMCClient(settings)
        resolved_domain = await client.ensure_domain_uuid()

        # 1) Collect devices + HA pairs + clusters
        devices = await client.list_device_records()
        ha_pairs = await client.list_device_ha_pairs()
        clusters = await client.list_device_clusters()

        if not (devices or ha_pairs or clusters):
            return json.dumps(
                {
                    "error": {
                        "category": "FMC_CLIENT",
                        "message": (
                            "No device records, HA pairs, or clusters found in FMC."
                        ),
                    }
                },
                indent=2,
            )

        # Wrap them with a 'kind' field so we know what we matched
        candidates: List[Dict[str, Any]] = []

        for dev in devices:
            candidates.append({"kind": "device", "record": dev})

        for ha in ha_pairs:
            candidates.append({"kind": "ha", "record": ha})

        for cl in clusters:
            candidates.append({"kind": "cluster", "record": cl})

        norm_target = target.strip().lower()
        exact_matches: List[Dict[str, Any]] = []
        partial_matches: List[Dict[str, Any]] = []

        for cand in candidates:
            rec = cand["record"]
            kind = cand["kind"]

            name = (rec.get("name") or "").lower()
            # hostName only makes sense on 'device' kind; HA/cluster usually do not have it
            host = ""
            if kind == "device":
                host = (rec.get("hostName") or "").lower()

            if norm_target == name or (host and norm_target == host):
                exact_matches.append(cand)
            elif norm_target and (
                (name and norm_target in name) or (host and norm_target in host)
            ):
                partial_matches.append(cand)

        chosen: Optional[Dict[str, Any]] = None
        resolution_note = ""

        if exact_matches:
            chosen = exact_matches[0]
            kinds = {c["kind"] for c in exact_matches}
            if len(exact_matches) > 1 or len(kinds) > 1:
                resolution_note = (
                    f"Multiple exact matches for '{target}' "
                    f"(kinds={sorted(kinds)}), picked the first."
                )
            else:
                resolution_note = "Exact match by name/hostName."
        elif partial_matches:
            chosen = partial_matches[0]
            kinds = {c["kind"] for c in partial_matches}
            if len(partial_matches) > 1 or len(kinds) > 1:
                resolution_note = (
                    f"Multiple partial matches for '{target}' "
                    f"(kinds={sorted(kinds)}), picked the first."
                )
            else:
                resolution_note = "Partial match by name/hostName."
        else:
            return json.dumps(
                {
                    "error": {
                        "category": "RESOLUTION",
                        "message": (
                            f"No device/HA/cluster record matched target '{target}'."
                        ),
                    }
                },
                indent=2,
            )

        record = chosen["record"]
        origin_kind = chosen["kind"]

        device_id = record.get("id")
        device_name = record.get("name")
        device_host = record.get("hostName") if origin_kind == "device" else None

        # 2) Get assigned Access Policy
        # First, check inline on the device/HA/cluster record
        policy = (
            record.get("accessPolicy")
            or record.get("policy")
            or record.get("devicePolicy")
        )

        # Some FMC objects (especially HA pairs / clusters) don't carry
        # the AccessPolicy inline; they are only visible via
        # /assignment/policyassignments. If we didn't find an AccessPolicy
        # on the record, or the type is not AccessPolicy, look it up there.
        if not policy or policy.get("type") != "AccessPolicy":
            assignments = await client.list_policy_assignments()
            target_id = device_id

            access_assignments: List[Dict[str, Any]] = []
            for assign in assignments:
                pol = assign.get("policy") or {}
                if pol.get("type") != "AccessPolicy":
                    continue
                for t in assign.get("targets") or []:
                    if t.get("id") == target_id:
                        access_assignments.append(assign)
                        break

            if access_assignments:
                chosen_assignment = access_assignments[0]
                policy = chosen_assignment.get("policy")
                extra_note = (
                    "AccessPolicy resolved via /assignment/policyassignments "
                    f"(assignmentId={chosen_assignment.get('id')})."
                )
                if resolution_note:
                    resolution_note = f"{resolution_note} {extra_note}"
                else:
                    resolution_note = extra_note

        if not policy or not policy.get("id"):
            return json.dumps(
                {
                    "error": {
                        "category": "RESOLUTION",
                        "message": (
                            f"Target '{device_name}' (kind={origin_kind}) does not have "
                            "an Access Policy assigned "
                            "(no inline accessPolicy/policy/devicePolicy and no "
                            "AccessPolicy policyassignment for this target)."
                        ),
                    }
                },
                indent=2,
            )

        access_policy_id = policy.get("id")
        access_policy_name = policy.get("name")

        # 3) Reuse the core search logic
        result_core = await _search_rules_for_query(client, query, access_policy_id)

        # 4) Augment with target / device info
        result_core["target"] = target
        result_core["resolved_device"] = {
            "kind": origin_kind,
            "id": device_id,
            "name": device_name,
            "hostName": device_host,
            "access_policy": {
                "id": access_policy_id,
                "name": access_policy_name,
                "type": policy.get("type"),
            },
        }
        result_core["resolution_note"] = resolution_note
        result_core["domain_uuid"] = resolved_domain  # ensure visible

        return json.dumps(result_core, indent=2)

    except FMCClientError as fmc_err:
        logger.error("FMCClientError in find_rules_for_target: %s", fmc_err)
        error_payload = {
            "error": {
                "category": "FMC_CLIENT",
                "message": str(fmc_err),
            }
        }
        return json.dumps(error_payload, indent=2)

    except Exception as exc:
        logger.exception("Unexpected error in find_rules_for_target")
        error_payload = {
            "error": {
                "category": "UNEXPECTED",
                "message": str(exc),
            }
        }
        return json.dumps(error_payload, indent=2)


def main() -> None:
    """
    Entry point for running as an MCP server.

    Transport is controlled by MCP_TRANSPORT:
      - "stdio" (default): for desktop MCP clients
      - "http"          : for Docker / remote agents (Streamable HTTP)
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    if transport == "http":
        host = os.getenv("MCP_HOST", "0.0.0.0")
        port_str = os.getenv("MCP_PORT", "8000")
        try:
            port = int(port_str)
        except ValueError:
            port = 8000

        logger.info(
            "Starting MCP server (transport=http) on %s:%s",
            host,
            port,
        )
        mcp.run(transport="http", host=host, port=port)
    else:
        logger.info("Starting MCP server (transport=stdio)")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
