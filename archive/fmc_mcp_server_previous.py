from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Literal

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

# Reduce httpx noise unless explicitly overridden
HTTPX_LOG_LEVEL = os.getenv("HTTPX_LOG_LEVEL", "INFO").upper()
logging.getLogger("httpx").setLevel(HTTPX_LOG_LEVEL)

# Limit paging for dynamic objects (these can be VERY heavy)
_dynamic_pages_env = os.getenv("FMC_DYNAMICOBJECT_MAX_PAGES", "5")
try:
    DYNAMICOBJECT_HARD_PAGE_LIMIT = max(1, int(_dynamic_pages_env))
except ValueError:
    DYNAMICOBJECT_HARD_PAGE_LIMIT = 5


# --------------------------------------------------------------------------------------
# Config & FMC client
# --------------------------------------------------------------------------------------


@dataclass
class FMCSettings:
    """
    Basic configuration for connecting to an FMC instance.

    In future, we can support multiple FMCs by having several FMCSettings
    instances loaded from a registry / config file, but for now we keep a
    single-FMC view using environment variables.
    """

    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: float = 30.0
    domain_uuid: Optional[str] = None

    @classmethod
    def from_env(cls) -> "FMCSettings":
        """
        Construct settings from environment variables.

        Required:
          - FMC_BASE_URL
          - FMC_USERNAME
          - FMC_PASSWORD

        Optional:
          - FMC_VERIFY_SSL (true/false/1/0/yes/no)
          - FMC_TIMEOUT (seconds, float)
          - FMC_DOMAIN_UUID
        """
        base_url = os.getenv("FMC_BASE_URL")
        username = os.getenv("FMC_USERNAME")
        password = os.getenv("FMC_PASSWORD")

        if not base_url or not username or not password:
            raise ValueError(
                "FMC_BASE_URL, FMC_USERNAME, and FMC_PASSWORD must be set in environment"
            )

        verify_env = os.getenv("FMC_VERIFY_SSL", "false").strip().lower()
        verify_ssl = verify_env in {"1", "true", "yes", "y"}

        timeout_str = os.getenv("FMC_TIMEOUT", "30").strip()
        try:
            timeout = float(timeout_str)
        except ValueError:
            logger.warning(
                "Invalid FMC_TIMEOUT=%s, falling back to 30 seconds", timeout_str
            )
            timeout = 30.0

        domain_uuid = os.getenv("FMC_DOMAIN_UUID")

        logger.debug(
            "Loaded FMC settings base_url=%s verify_ssl=%s timeout=%s domain_uuid=%s",
            base_url,
            verify_ssl,
            timeout,
            domain_uuid,
        )

        return cls(
            base_url=base_url.rstrip("/"),
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            domain_uuid=domain_uuid,
        )


class FMCClientError(Exception):
    """Base exception for FMC client errors."""


class FMCAuthError(FMCClientError):
    """Authentication / token issues."""


class FMCRequestError(FMCClientError):
    """HTTP/network problems when talking to FMC."""


class FMCClient:
    """
    Minimal async FMC REST API client.

    This client is intentionally small and focused on:
      - Auth / token management
      - Domain resolution
      - Listing devices / policies / rules
      - Listing network-related objects

    All methods are designed to be called from MCP tools, with solid logging
    and defensive error handling.
    """

    def __init__(self, settings: FMCSettings) -> None:
        self._settings = settings
        self._access_token: Optional[str] = None
        self._domain_uuid: Optional[str] = settings.domain_uuid

    # ---- Token management ------------------------------------------------------------

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
                    auth=(self._settings.username, self._settings.password),
                    headers={"Content-Type": "application/json"},
                )
        except httpx.RequestError as exc:
            logger.error("FMC auth request failed: %s", exc)
            raise FMCAuthError(f"Failed to authenticate to FMC: {exc}") from exc

        if response.status_code not in (200, 204):
            logger.error(
                "FMC auth failed with status %s: %s",
                response.status_code,
                response.text,
            )
            raise FMCAuthError(
                f"Authentication failed with status {response.status_code}: {response.text}"
            )

        token = response.headers.get("X-auth-access-token")
        if not token:
            logger.error("FMC auth response did not include X-auth-access-token")
            raise FMCAuthError("No X-auth-access-token returned by FMC")

        logger.debug("FMC auth successful, token obtained")
        self._access_token = token

    async def _ensure_authenticated(self) -> None:
        """Authenticate if we don't have a token yet."""
        if not self._access_token:
            await self._authenticate()

    # ---- Domain resolution -----------------------------------------------------------

    async def ensure_domain_uuid(self) -> str:
        """
        Ensure we have a domain UUID to use in config URLs.

        If FMCSettings.domain_uuid is provided, we use it as-is.
        Otherwise we call /api/fmc_platform/v1/info/domain once and cache it.
        """
        if self._domain_uuid:
            return self._domain_uuid

        await self._ensure_authenticated()
        url = f"{self._settings.base_url}/api/fmc_platform/v1/info/domain"
        logger.debug("Resolving FMC domain UUID via %s", url)

        try:
            async with httpx.AsyncClient(
                verify=self._settings.verify_ssl, timeout=self._settings.timeout
            ) as client:
                response = await client.get(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "X-auth-access-token": self._access_token or "",
                    },
                )
        except httpx.RequestError as exc:
            logger.error("FMC domain info request failed: %s", exc)
            raise FMCRequestError(f"Failed to query FMC domain info: {exc}") from exc

        if response.status_code != 200:
            logger.error(
                "FMC domain info failed with status %s: %s",
                response.status_code,
                response.text,
            )
            raise FMCRequestError(
                f"Domain info failed with status {response.status_code}: {response.text}"
            )

        data = response.json()
        items = data.get("items") or []
        if not items:
            raise FMCRequestError("FMC domain info returned no domains")

        # In single-domain scenarios, this is typically a single item
        domain_uuid = items[0].get("uuid")
        if not domain_uuid:
            raise FMCRequestError("FMC domain info did not include a uuid")

        logger.info("Resolved FMC domain UUID to %s", domain_uuid)
        self._domain_uuid = domain_uuid
        return domain_uuid

    # ---- Core request helper ---------------------------------------------------------

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
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

        # Token expired? Try once to refresh and retry.
        if response.status_code == 401:
            logger.warning("FMC request got 401, refreshing token and retrying once")
            self._access_token = None
            await self._ensure_authenticated()
            headers["X-auth-access-token"] = self._access_token or ""
            try:
                async with httpx.AsyncClient(
                    verify=self._settings.verify_ssl,
                    timeout=self._settings.timeout,
                ) as client:
                    response = await client.request(
                        method=method, url=url, headers=headers, params=params
                    )
            except httpx.RequestError as exc:
                logger.error(
                    "FMC %s %s failed after token refresh: %s", method, url, exc
                )
                raise FMCRequestError(
                    f"FMC {method} {url} failed after token refresh: {exc}"
                ) from exc

        if ignore_statuses and response.status_code in ignore_statuses:
            logger.info(
                "FMC %s %s got status %s (ignored)",
                method,
                url,
                response.status_code,
            )
            # Return an "empty list" style payload
            return {"items": [], "paging": {}}

        if response.status_code < 200 or response.status_code >= 300:
            logger.error(
                "FMC %s %s failed with status %s: %s",
                method,
                url,
                response.status_code,
                response.text,
            )
            raise FMCRequestError(
                f"FMC {method} {url} failed with status {response.status_code}: {response.text}"
            )

        try:
            return response.json()
        except json.JSONDecodeError as exc:
            logger.error(
                "FMC %s %s returned non-JSON response: %s", method, url, response.text
            )
            raise FMCRequestError(
                f"FMC {method} {url} returned invalid JSON: {exc}"
            ) from exc

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

            data = await self._request_json(
                "GET", path, params=query_params, ignore_statuses=ignore_statuses
            )
            items = data.get("items") or []
            paging = data.get("paging") or {}

            all_items.extend(items)
            page_count += 1

            logger.debug(
                "FMC paging path=%s page=%s got=%s total so far=%s",
                path,
                page_count,
                len(items),
                len(all_items),
            )

            if not items:
                break

            # 'paging.next' style
            next_link = paging.get("next")
            if not next_link:
                break

            # FMC uses explicit next offset; but to keep it robust, we can
            # also just increment by 'limit' if needed.
            next_offset = paging.get("offset", offset + limit)
            offset = next_offset

            if page_count >= hard_page_limit:
                logger.warning(
                    "FMC paging for %s hit hard_page_limit=%s, stopping",
                    path,
                    hard_page_limit,
                )
                break

        return all_items

    # ---- Device & policy helpers -----------------------------------------------------

    async def list_device_records(self) -> List[Dict[str, Any]]:
        """
        List device records (FTD/ASA/etc.) from FMC.

        Uses:
          GET /api/fmc_config/v1/domain/{domain_UUID}/devices/devicerecords
        """
        return await self._list_paginated(
            "/devices/devicerecords",
            expanded=True,
            hard_page_limit=5,
        )

    async def list_device_ha_pairs(self) -> List[Dict[str, Any]]:
        """
        List HA pairs from FMC.

        Uses:
          GET /api/fmc_config/v1/domain/{domain_UUID}/devices/ftddevicehapairs
        """
        return await self._list_paginated(
            "/devices/ftddevicehapairs",
            expanded=True,
            hard_page_limit=5,
        )

    async def list_device_clusters(self) -> List[Dict[str, Any]]:
        """
        List device clusters from FMC.

        Uses:
          GET /api/fmc_config/v1/domain/{domain_UUID}/devices/ftddeviceclusters
        """
        return await self._list_paginated(
            "/devices/ftddeviceclusters",
            expanded=True,
            hard_page_limit=5,
        )

    async def list_policy_assignments(self) -> List[Dict[str, Any]]:
        """
        List policy assignments.

        Uses:
          GET /api/fmc_config/v1/domain/{domain_UUID}/assignment/policyassignments
        """
        return await self._list_paginated(
            "/assignment/policyassignments",
            expanded=True,
            hard_page_limit=5,
        )

    # ---- Access policies & rules -----------------------------------------------------

    async def list_access_policies(
        self,
        *,
        limit: int = 1000,
        hard_page_limit: int = 10,
        expanded: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve Access Control Policies in the current domain.

        Wraps:
          GET /api/fmc_config/v1/domain/{domain_UUID}/policy/accesspolicies
        """
        params: Dict[str, Any] = {}
        return await self._list_paginated(
            "/policy/accesspolicies",
            params=params,
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=expanded,
        )

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
        path_suffix = f"/policy/accesspolicies/{access_policy_id}/accessrules"

        return await self._list_paginated(
            path_suffix,
            params=params,
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=expanded,
        )

    # ---- Network object helpers ------------------------------------------------------

    async def list_host_objects(self) -> List[Dict[str, Any]]:
        """List /object/hosts."""
        return await self._list_paginated(
            "/object/hosts",
            expanded=True,
        )

    async def list_network_objects(self) -> List[Dict[str, Any]]:
        """List /object/networks."""
        return await self._list_paginated(
            "/object/networks",
            expanded=True,
        )

    async def list_range_objects(self) -> List[Dict[str, Any]]:
        """List /object/ranges."""
        return await self._list_paginated(
            "/object/ranges",
            expanded=True,
        )

    async def list_fqdn_objects(self) -> List[Dict[str, Any]]:
        """
        List /object/fqdns.

        On older FMC where this endpoint does not exist, a 404 is treated as
        "no FQDN objects" instead of an error.
        """
        return await self._list_paginated(
            "/object/fqdns",
            expanded=True,
            ignore_statuses={404},
        )

    async def list_network_groups(self) -> List[Dict[str, Any]]:
        """List /object/networkgroups."""
        return await self._list_paginated(
            "/object/networkgroups",
            expanded=True,
        )

    async def list_dynamic_objects(self) -> List[Dict[str, Any]]:
        """
        List /object/dynamicobjects.

        On older FMC where this endpoint does not exist, a 404 is treated as
        "no dynamic objects" instead of an error.

        Paging is limited by DYNAMICOBJECT_HARD_PAGE_LIMIT to avoid hammering FMC.
        """
        return await self._list_paginated(
            "/object/dynamicobjects",
            expanded=True,
            hard_page_limit=DYNAMICOBJECT_HARD_PAGE_LIMIT,
            ignore_statuses={404},
        )


# --------------------------------------------------------------------------------------
# IP / FQDN matching helpers
# --------------------------------------------------------------------------------------


class QueryKind:
    IP = "ip"
    NETWORK = "network"
    FQDN = "fqdn"


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


# Strict indicator validation helpers --------------------------------------------------

# Stricter FQDN: at least one dot, labels 1–63 chars, and last label letters only (2+)
FQDN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)


class InvalidIndicatorError(ValueError):
    """Raised when the indicator string is not a valid IP, CIDR, or FQDN."""


def classify_indicator(
    indicator: str,
    indicator_type: str = "auto",
) -> Tuple[str, Any]:
    """Validate and classify an indicator string as IP, NETWORK, or FQDN.

    Builds on :func:`parse_query` but adds stricter checks for FQDNs and
    honours the optional ``indicator_type`` hint.

    Args:
        indicator: Raw indicator string from the user (IP, CIDR, or FQDN).
        indicator_type:
            - "auto"  : infer kind from the value (default)
            - "ip"    : must be a single IP address
            - "subnet": must be a CIDR network
            - "fqdn"  : must be a valid FQDN
    """
    kind, value = parse_query(indicator)
    value_str = str(value)

    # Additional guard: strings that *look* like IPv4 dotted-decimal but are invalid
    # (e.g. "192.999.0.1") should not silently become FQDNs in "auto" mode.
    looks_like_ipv4 = bool(re.fullmatch(r"\d+(\.\d+){1,3}", indicator.strip()))

    # Enforce stricter FQDN syntax and require alphabetic characters
    if kind == QueryKind.FQDN:
        has_alpha = bool(re.search(r"[A-Za-z]", value_str))
        if indicator_type == "auto":
            if looks_like_ipv4 or not has_alpha or not FQDN_PATTERN.match(value_str):
                raise InvalidIndicatorError(
                    f"'{indicator}' is not a valid IP, CIDR, or FQDN."
                )
        else:  # indicator_type == 'fqdn' or any explicit
            if not has_alpha or not FQDN_PATTERN.match(value_str):
                raise InvalidIndicatorError(
                    f"'{indicator}' is not a syntactically valid FQDN."
                )

    if indicator_type == "auto":
        return kind, value

    if indicator_type == "ip":
        if kind != QueryKind.IP:
            raise InvalidIndicatorError(
                f"Expected an IP address but got '{kind}' for '{indicator}'."
            )
        return kind, value

    if indicator_type == "subnet":
        if kind != QueryKind.NETWORK:
            raise InvalidIndicatorError(
                f"Expected a CIDR network but got '{kind}' for '{indicator}'."
            )
        return kind, value

    if indicator_type == "fqdn":
        if kind != QueryKind.FQDN:
            raise InvalidIndicatorError(
                f"Expected an FQDN but got '{kind}' for '{indicator}'."
            )
        return kind, value

    raise InvalidIndicatorError(
        "Unsupported indicator_type '%s'. Use 'auto', 'ip', 'subnet', or 'fqdn'."
        % indicator_type
    )


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
    Collect literals in a network block (source/destination) that match the query.
    """
    if not network_block:
        return []

    matches: List[Dict[str, Any]] = []
    for lit in network_block.get("literals") or []:
        if literal_matches(query_kind, query_value, lit):
            matches.append(lit)
    return matches


# --------------------------------------------------------------------------------------
# Network object index for rule/object matching
# --------------------------------------------------------------------------------------


@dataclass
class AddressInterval:
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
            logger.debug("Skipping invalid host object %s=%s", obj_id, ip_str)
            return

        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="Host",
            intervals=[self._ip_to_interval(ip)],
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
            logger.debug("Skipping invalid network object %s=%s", obj_id, value)
            return

        self.by_id[obj_id] = NetworkObject(
            id=obj_id,
            name=name,
            type="Network",
            intervals=[self._network_to_interval(net)],
        )

    def add_range(self, obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        name = obj.get("name") or obj_id
        start_ip_str = obj.get("startIpAddress")
        end_ip_str = obj.get("endIpAddress")
        if not obj_id or not start_ip_str or not end_ip_str:
            return
        try:
            start_ip = ipaddress.ip_address(start_ip_str)
            end_ip = ipaddress.ip_address(end_ip_str)
            interval = self._range_to_interval(start_ip, end_ip)
        except ValueError:
            logger.debug(
                "Skipping invalid range object %s=%s-%s",
                obj_id,
                start_ip_str,
                end_ip_str,
            )
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

        # literals (IPs, networks, FQDNs)
        self._add_literals_to_object(netobj, obj.get("literals") or [])

        self.by_id[obj_id] = netobj

    def add_dynamic_object(self, obj: Dict[str, Any]) -> None:
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

        # nested objects
        for child in obj.get("objects") or []:
            child_id = child.get("id")
            if child_id:
                netobj.member_ids.append(child_id)

        # nested literals (where present)
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

        # 2) FQDN direct list
        if query_kind == QueryKind.FQDN and netobj.fqdns:
            if query_value in netobj.fqdns:
                return True

        # 3) Nested members for NetworkGroups / DynamicObjects
        if netobj.member_ids:
            for member_id in netobj.member_ids:
                child = self.by_id.get(member_id)
                if child and self._object_matches(
                    child,
                    query_kind,
                    query_value,
                    query_intervals,
                    visited=visited,
                ):
                    return True

        return False

    def match_objects(
        self, query_kind: str, query_value: Any
    ) -> List[NetworkObject]:
        """
        Return all objects that match query.
        """
        results: List[NetworkObject] = []
        query_intervals = self._build_query_intervals(query_kind, query_value)

        for obj in self.by_id.values():
            try:
                if self._object_matches(
                    obj, query_kind, query_value, query_intervals
                ):
                    results.append(obj)
            except Exception as exc:
                logger.debug("Error matching object %s: %s", obj.id, exc)

        return results


# --------------------------------------------------------------------------------------
# Shared search helper (single policy)
# --------------------------------------------------------------------------------------


async def _search_rules_for_query(
    client: FMCClient,
    query: str,
    access_policy_id: str,
) -> Dict[str, Any]:
    """
    Core logic shared by find_rules_by_ip_or_fqdn and find_rules_for_target:

      - validate/query classify (IP, subnet, FQDN)
      - build object index
      - find matching objects
      - fetch rules (expanded=true)
      - find literal & object matches

    Returns a dict (not JSON string).
    """
    resolved_domain = await client.ensure_domain_uuid()
    settings = client.settings

    # Use stricter indicator validation here as well
    try:
        query_kind, query_value = classify_indicator(query, "auto")
    except InvalidIndicatorError as ind_err:
        raise FMCClientError(f"Invalid query indicator: {ind_err}") from ind_err

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

    fqdns = await client.list_fqdn_objects()
    for obj in fqdns:
        obj_index.add_fqdn(obj)

    groups = await client.list_network_groups()
    for obj in groups:
        obj_index.add_network_group(obj)

    dynamics = await client.list_dynamic_objects()
    for obj in dynamics:
        obj_index.add_dynamic_object(obj)

    logger.info(
        "Indexed %s network objects (hosts=%s networks=%s ranges=%s fqdns=%s groups=%s dynamics=%s)",
        len(obj_index.by_id),
        len(hosts),
        len(networks),
        len(ranges),
        len(fqdns),
        len(groups),
        len(dynamics),
    )

    # Find all matching objects for the query
    matching_objects = obj_index.match_objects(query_kind, query_value)
    logger.info("Found %s matching network/FQDN objects", len(matching_objects))

    # Map object id -> summary for quick lookup
    matched_object_ids: Dict[str, Dict[str, Any]] = {}
    for netobj in matching_objects:
        matched_object_ids[netobj.id] = {
            "id": netobj.id,
            "name": netobj.name,
            "type": netobj.type,
            "fqdns": netobj.fqdns,
            "has_intervals": bool(netobj.intervals),
            "members": netobj.member_ids,
        }

    # 2) Fetch expanded access rules for the policy
    logger.info("Fetching Access Control rules for policy %s", access_policy_id)
    rules = await client.list_access_rules(access_policy_id, expanded=True)

    logger.info("Loaded %s rules from policy %s", len(rules), access_policy_id)

    matched_rules: List[Dict[str, Any]] = []

    for rule in rules:
        src_block = (rule.get("sourceNetworks") or {}).copy()
        dst_block = (rule.get("destinationNetworks") or {}).copy()

        # Literal IP / network matching
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
                    "id": obj_id,
                    "name": ref.get("name") or match.get("name"),
                    "type": ref.get("type") or match.get("type"),
                }
                src_object_matches.append(enriched)

        for ref in dst_block.get("objects") or []:
            obj_id = ref.get("id")
            if not obj_id:
                continue
            match = matched_object_ids.get(obj_id)
            if match:
                enriched = {
                    "id": obj_id,
                    "name": ref.get("name") or match.get("name"),
                    "type": ref.get("type") or match.get("type"),
                }
                dst_object_matches.append(enriched)

        if not (
            src_lit_matches
            or dst_lit_matches
            or src_object_matches
            or dst_object_matches
        ):
            continue  # no match at all

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
         - Dynamic objects (/object/dynamicobjects, where available)
      2. Scan Access Control rules in the specified Access Policy:
         - sourceNetworks.literals / destinationNetworks.literals
         - sourceNetworks.objects / destinationNetworks.objects
      3. Return a JSON summary containing:
         - matched FMC network/FQDN objects
         - rules that reference them (or literals matching the query)

    Parameters:
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
            record = cand["record"]
            name = (record.get("name") or "").strip()
            host_name = (record.get("hostName") or "").strip()

            name_lower = name.lower()
            host_lower = host_name.lower()

            if norm_target == name_lower or (host_lower and norm_target == host_lower):
                exact_matches.append(cand)
            elif norm_target in name_lower or (
                host_lower and norm_target in host_lower
            ):
                partial_matches.append(cand)

        if not exact_matches and not partial_matches:
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

        # Prefer exact matches; fall back to partial
        chosen = None
        origin_kind = ""
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

        origin_kind = chosen["kind"]
        record = chosen["record"]
        device_id = record.get("id")
        device_name = record.get("name")
        device_host = record.get("hostName")

        if not device_id:
            return json.dumps(
                {
                    "error": {
                        "category": "RESOLUTION",
                        "message": (
                            f"Chosen record for target '{target}' has no id; "
                            "cannot resolve policy."
                        ),
                    }
                },
                indent=2,
            )

        # 2) Try to resolve Access Policy:
        # First, look for an inline "accessPolicy" reference
        policy = (record.get("accessPolicy") or {}).copy()

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

            if not access_assignments:
                return json.dumps(
                    {
                        "error": {
                            "category": "RESOLUTION",
                            "message": (
                                f"No Access Policy assignment found for target '{target}'."
                            ),
                        }
                    },
                    indent=2,
                )

            if len(access_assignments) > 1:
                logger.warning(
                    "Multiple AccessPolicy assignments found for %s, using first",
                    target,
                )

            chosen_assign = access_assignments[0]
            policy = chosen_assign.get("policy") or {}

        if not policy or policy.get("type") != "AccessPolicy":
            return json.dumps(
                {
                    "error": {
                        "category": "RESOLUTION",
                        "message": (
                            f"Could not resolve Access Policy for target '{target}'."
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


@mcp.tool()
async def search_access_rules(
    indicator: str,
    indicator_type: Literal["auto", "ip", "subnet", "fqdn"] = "auto",
    scope: Literal["policy", "fmc"] = "fmc",
    policy_name: Optional[str] = None,
    max_results: int = 100,
    domain_uuid: Optional[str] = None,
) -> Dict[str, Any]:
    """FMC-driven rule search for an IP/CIDR/FQDN across Access Policies.

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
    # Clamp max_results to a safe range
    if max_results < 1:
        max_results = 1
    elif max_results > 500:
        max_results = 500

    if scope not in ("policy", "fmc"):
        return {
            "error": {
                "category": "VALIDATION",
                "message": f"Unsupported scope '{scope}'. Use 'policy' or 'fmc'.",
            }
        }

    if scope == "policy" and not policy_name:
        return {
            "error": {
                "category": "VALIDATION",
                "message": "scope='policy' requires a non-empty policy_name.",
            }
        }

    try:
        settings = FMCSettings.from_env()
        if domain_uuid:
            settings.domain_uuid = domain_uuid

        client = FMCClient(settings)

        # Validate / classify the indicator before any FMC calls
        try:
            kind, value = classify_indicator(indicator, indicator_type)
        except InvalidIndicatorError as ind_err:
            logger.info("Invalid indicator '%s': %s", indicator, ind_err)
            return {
                "error": {
                    "category": "INVALID_INDICATOR",
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "message": str(ind_err),
                }
            }

        # Determine effective indicator_type for the response
        if kind == QueryKind.IP:
            effective_indicator_type = "ip"
        elif kind == QueryKind.NETWORK:
            effective_indicator_type = "subnet"
        else:
            effective_indicator_type = "fqdn"

        # Fetch Access Policies on this FMC/domain (with expanded=true)
        policies = await client.list_access_policies(
            limit=1000,
            hard_page_limit=10,
            expanded=True,
        )

        if not policies:
            return {
                "error": {
                    "category": "FMC_CLIENT",
                    "message": "No Access Policies found on FMC.",
                }
            }

        # Filter policies if scope=policy
        policy_filter_name = None
        filtered_policies: List[Dict[str, Any]] = []

        if scope == "policy":
            norm_policy = policy_name.strip().lower()  # type: ignore[union-attr]
            for pol in policies:
                name = (pol.get("name") or "").strip()
                if name.lower() == norm_policy:
                    filtered_policies.append(pol)
            if not filtered_policies:
                available = sorted(
                    (p.get("name") or "").strip()
                    for p in policies
                    if p.get("name")
                )
                return {
                    "error": {
                        "category": "RESOLUTION",
                        "message": (
                            f"No Access Policy named '{policy_name}' was found "
                            "on this FMC/domain."
                        ),
                        "available_policies": available,
                    }
                }
            policy_filter_name = policy_name
        else:
            filtered_policies = policies

        # ------------------------------------------------------------------
        # Build network object index ONCE for this whole search
        # ------------------------------------------------------------------
        query_kind = kind
        query_value = value

        logger.info("Loading FMC network objects for matching (FMC-wide search)...")
        obj_index = NetworkObjectIndex()

        hosts = await client.list_host_objects()
        for obj in hosts:
            obj_index.add_host(obj)

        networks = await client.list_network_objects()
        for obj in networks:
            obj_index.add_network(obj)

        ranges = await client.list_range_objects()
        for obj in ranges:
            obj_index.add_range(obj)

        fqdns = await client.list_fqdn_objects()
        for obj in fqdns:
            obj_index.add_fqdn(obj)

        groups = await client.list_network_groups()
        for obj in groups:
            obj_index.add_network_group(obj)

        dynamics = await client.list_dynamic_objects()
        for obj in dynamics:
            obj_index.add_dynamic_object(obj)

        logger.info(
            "Indexed %s network objects for FMC search (hosts=%s networks=%s ranges=%s fqdns=%s groups=%s dynamics=%s)",
            len(obj_index.by_id),
            len(hosts),
            len(networks),
            len(ranges),
            len(fqdns),
            len(groups),
            len(dynamics),
        )

        matching_objects = obj_index.match_objects(query_kind, query_value)
        logger.info(
            "FMC-wide search: found %s matching network/FQDN objects",
            len(matching_objects),
        )

        matched_object_ids: Dict[str, Dict[str, Any]] = {}
        for netobj in matching_objects:
            matched_object_ids[netobj.id] = {
                "id": netobj.id,
                "name": netobj.name,
                "type": netobj.type,
                "fqdns": netobj.fqdns,
                "has_intervals": bool(netobj.intervals),
                "members": netobj.member_ids,
            }

        # ------------------------------------------------------------------
        # For each policy, fetch rules and see which ones reference the
        # literals or objects matching the indicator.
        # ------------------------------------------------------------------
        matched_items: List[Dict[str, Any]] = []
        scanned_policies = 0
        truncated = False

        for pol in filtered_policies:
            policy_id = pol.get("id")
            policy_name_val = pol.get("name")
            if not policy_id:
                continue

            scanned_policies += 1

            logger.info(
                "FMC-wide search: Fetching rules for Access Policy %s (%s)",
                policy_name_val,
                policy_id,
            )
            rules = await client.list_access_rules(policy_id, expanded=True)
            logger.info(
                "FMC-wide search: Loaded %s rules from policy %s",
                len(rules),
                policy_id,
            )

            for rule in rules:
                src_block = (rule.get("sourceNetworks") or {}).copy()
                dst_block = (rule.get("destinationNetworks") or {}).copy()

                # Literal IP / network/FQDN matching
                src_lit_matches = collect_matching_literals(
                    query_kind, query_value, src_block
                )
                dst_lit_matches = collect_matching_literals(
                    query_kind, query_value, dst_block
                )

                # Object matches (by id) using the pre-built matched_object_ids
                src_object_matches: List[Dict[str, Any]] = []
                dst_object_matches: List[Dict[str, Any]] = []

                for ref in src_block.get("objects") or []:
                    obj_id = ref.get("id")
                    if not obj_id:
                        continue
                    match = matched_object_ids.get(obj_id)
                    if match:
                        enriched = {
                            "id": obj_id,
                            "name": ref.get("name") or match.get("name"),
                            "type": ref.get("type") or match.get("type"),
                        }
                        src_object_matches.append(enriched)

                for ref in dst_block.get("objects") or []:
                    obj_id = ref.get("id")
                    if not obj_id:
                        continue
                    match = matched_object_ids.get(obj_id)
                    if match:
                        enriched = {
                            "id": obj_id,
                            "name": ref.get("name") or match.get("name"),
                            "type": ref.get("type") or match.get("type"),
                        }
                        dst_object_matches.append(enriched)

                if not (
                    src_lit_matches
                    or dst_lit_matches
                    or src_object_matches
                    or dst_object_matches
                ):
                    continue

                rule_entry = {
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

                matched_items.append(
                    {
                        "policy": {
                            "id": policy_id,
                            "name": policy_name_val,
                        },
                        "rule": rule_entry,
                    }
                )

                if len(matched_items) >= max_results:
                    truncated = True
                    break

            if len(matched_items) >= max_results:
                break

        resolved_domain = await client.ensure_domain_uuid()

        meta: Dict[str, Any] = {
            "indicator": indicator,
            "indicator_type": effective_indicator_type,
            "scope": scope,
            "fmc": {
                "base_url": settings.base_url,
                "domain_uuid": resolved_domain,
            },
            "policies_scanned": scanned_policies,
            "matched_rules_count": len(matched_items),
            "matched_object_count": len(matching_objects),
            "truncated": truncated,
        }
        if policy_filter_name:
            meta["policy_filter"] = policy_filter_name

        return {
            "meta": meta,
            "items": matched_items,
        }

    except FMCClientError as fmc_err:
        logger.error("FMCClientError in search_access_rules: %s", fmc_err)
        return {
            "error": {
                "category": "FMC_CLIENT",
                "message": str(fmc_err),
            }
        }
    except Exception as exc:
        logger.exception("Unexpected error in search_access_rules")
        return {
            "error": {
                "category": "UNEXPECTED",
                "message": str(exc),
            }
        }


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
            logger.warning("Invalid MCP_PORT=%s, falling back to 8000", port_str)
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
