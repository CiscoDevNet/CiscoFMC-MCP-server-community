from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

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
      - Listing devices/policies/rules
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

            if not items:
                break

            next_link = paging.get("next")
            if not next_link:
                break

            offset = paging.get("offset", offset + limit)

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
