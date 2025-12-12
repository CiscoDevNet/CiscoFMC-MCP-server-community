from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlsplit

import httpx

from ..config import FMCSettings
from ..errors import FMCAuthError, FMCRequestError
from ..logging_conf import configure_logging

logger = configure_logging("sfw-mcp-fmc")


class FMCClient:
    """
    Minimal async FMC REST API client focused on:
      - Auth/token management
      - Domain resolution
      - Listing policies / rules
      - Listing network-related objects
    """

    def __init__(self, settings: FMCSettings) -> None:
        self._settings = settings
        self._access_token: Optional[str] = None
        self._domain_uuid: Optional[str] = settings.domain_uuid

    @property
    def settings(self) -> FMCSettings:
        return self._settings

    async def _authenticate(self) -> None:
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
            raise FMCAuthError(f"Failed to authenticate to FMC: {exc}") from exc

        if response.status_code not in (200, 204):
            raise FMCAuthError(
                f"Authentication failed with status {response.status_code}: {response.text}"
            )

        token = response.headers.get("X-auth-access-token")
        if not token:
            raise FMCAuthError("No X-auth-access-token returned by FMC")

        self._access_token = token

    async def _ensure_authenticated(self) -> None:
        if not self._access_token:
            await self._authenticate()

    async def ensure_domain_uuid(self) -> str:
        if self._domain_uuid:
            return self._domain_uuid

        await self._ensure_authenticated()
        url = f"{self._settings.base_url}/api/fmc_platform/v1/info/domain"

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
            raise FMCRequestError(f"Failed to query FMC domain info: {exc}") from exc

        if response.status_code != 200:
            raise FMCRequestError(
                f"Domain info failed with status {response.status_code}: {response.text}"
            )

        data = response.json()
        items = data.get("items") or []
        if not items:
            raise FMCRequestError("FMC domain info returned no domains")

        domain_uuid = items[0].get("uuid")
        if not domain_uuid:
            raise FMCRequestError("FMC domain info did not include a uuid")

        self._domain_uuid = domain_uuid
        return domain_uuid

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        ignore_statuses: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        await self._ensure_authenticated()
        if not self._access_token:
            raise FMCAuthError("No access token, authentication failed")

        url = f"{self._settings.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": self._access_token,
        }

        try:
            async with httpx.AsyncClient(
                verify=self._settings.verify_ssl, timeout=self._settings.timeout
            ) as client:
                response = await client.request(
                    method=method, url=url, headers=headers, params=params
                )
        except httpx.RequestError as exc:
            raise FMCRequestError(f"FMC {method} {url} failed: {exc}") from exc

        if response.status_code == 401:
            # refresh once
            self._access_token = None
            await self._ensure_authenticated()
            headers["X-auth-access-token"] = self._access_token or ""
            try:
                async with httpx.AsyncClient(
                    verify=self._settings.verify_ssl, timeout=self._settings.timeout
                ) as client:
                    response = await client.request(
                        method=method, url=url, headers=headers, params=params
                    )
            except httpx.RequestError as exc:
                raise FMCRequestError(
                    f"FMC {method} {url} failed after token refresh: {exc}"
                ) from exc

        if ignore_statuses and response.status_code in ignore_statuses:
            return {"items": [], "paging": {}}

        if response.status_code < 200 or response.status_code >= 300:
            raise FMCRequestError(
                f"FMC {method} {url} failed with status {response.status_code}: {response.text}"
            )

        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise FMCRequestError(
                f"FMC {method} {url} returned invalid JSON: {exc}"
            ) from exc

    @staticmethod
    def _next_offset_from_paging(paging: Dict[str, Any], current_offset: int, limit: int) -> Optional[int]:
        """
        FMC paging is not consistent across resources. Some endpoints return paging.next with
        a URL that includes offset/limit; some return offset fields that do not advance.
        We parse paging.next when possible, else fall back to offset+limit.
        """
        next_link = paging.get("next")
        if next_link:
            try:
                q = parse_qs(urlsplit(str(next_link)).query)
                if "offset" in q:
                    return int(q["offset"][0])
            except Exception:
                pass

        # Fallback: advance by limit
        return current_offset + limit

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
        domain_uuid = await self.ensure_domain_uuid()
        path = f"/api/fmc_config/v1/domain/{domain_uuid}{path_suffix}"

        all_items: List[Dict[str, Any]] = []
        offset = 0
        page_count = 0

        base_params = params.copy() if params else {}
        base_params.setdefault("limit", limit)
        if expanded:
            base_params.setdefault("expanded", "true")

        last_offset = -1

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

            # Stop if no more items
            if not items:
                break

            # Stop if no paging.next and count < limit (common final page)
            if not paging.get("next") and len(items) < int(base_params.get("limit", limit)):
                break

            # Compute next offset safely
            next_offset = self._next_offset_from_paging(paging, offset, int(base_params.get("limit", limit)))

            # Guard against non-advancing offsets
            if next_offset is None or next_offset == offset or next_offset == last_offset:
                break

            last_offset = offset
            offset = next_offset

            if page_count >= hard_page_limit:
                logger.warning(
                    "Paging for %s hit hard_page_limit=%s, stopping",
                    path,
                    hard_page_limit,
                )
                break

        return all_items

    # Devices / assignments
    async def list_device_records(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/devices/devicerecords", expanded=True, hard_page_limit=5)

    async def list_device_ha_pairs(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/devices/ftddevicehapairs", expanded=True, hard_page_limit=5)

    async def list_device_clusters(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/devices/ftddeviceclusters", expanded=True, hard_page_limit=5)

    async def list_policy_assignments(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/assignment/policyassignments", expanded=True, hard_page_limit=5)

    # Access policies / rules
    async def list_access_policies(
        self, *, limit: int = 1000, hard_page_limit: int = 10, expanded: bool = True
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/policy/accesspolicies", limit=limit, hard_page_limit=hard_page_limit, expanded=expanded
        )

    async def list_access_rules(
        self, access_policy_id: str, *, limit: int = 1000, hard_page_limit: int = 10, expanded: bool = True
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            f"/policy/accesspolicies/{access_policy_id}/accessrules",
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=expanded,
        )

    # Prefilter policies / rules (NEW)
    async def list_prefilter_policies(
        self, *, limit: int = 1000, hard_page_limit: int = 10, expanded: bool = True
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/policy/prefilterpolicies", limit=limit, hard_page_limit=hard_page_limit, expanded=expanded
        )

    async def list_prefilter_rules(
        self, prefilter_policy_id: str, *, limit: int = 1000, hard_page_limit: int = 10, expanded: bool = True
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            f"/policy/prefilterpolicies/{prefilter_policy_id}/prefilterrules",
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=expanded,
        )

    # Network objects
    async def list_host_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/object/hosts", expanded=True)

    async def list_network_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/object/networks", expanded=True)

    async def list_range_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/object/ranges", expanded=True)

    async def list_fqdn_objects(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/object/fqdns", expanded=True, ignore_statuses={404})

    async def list_network_groups(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/object/networkgroups", expanded=True)

    async def list_dynamic_objects(self, hard_page_limit: int) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/object/dynamicobjects", expanded=True, hard_page_limit=hard_page_limit, ignore_statuses={404}
        )
