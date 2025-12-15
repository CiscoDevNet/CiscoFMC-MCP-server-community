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

    @staticmethod
    def _expanded_param_enabled(params: Optional[Dict[str, Any]]) -> bool:
        if not params:
            return False
        v = params.get("expanded")
        if v is None:
            return False
        return str(v).strip().lower() in {"true", "1", "yes"}

    @staticmethod
    def _looks_like_expanded_rejected(resp: httpx.Response) -> bool:
        """
        Heuristic to avoid masking real 400s: only fallback if response body
        mentions 'expanded' (common FMC error text for unsupported query param).
        """
        try:
            text = (resp.text or "").lower()
        except Exception:
            text = ""
        if "expanded" in text:
            return True

        # Some FMC responses are JSON with message/description fields
        try:
            j = resp.json()
            blob = json.dumps(j).lower()
            return "expanded" in blob
        except Exception:
            return False

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        ignore_statuses: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        await self._ensure_authenticated()
        if not self._access_token:
            raise RuntimeError("No access token available")

        base = self._settings.base_url.rstrip("/")

        # ✅ Fully-qualified URL
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            p = path.lstrip("/")

            # ✅ Explicit API paths (platform or config)
            if p.startswith("api/"):
                url = f"{base}/{p}"
            else:
                # ✅ Relative config paths (auto-prefix domain URL)
                domain_uuid = await self.ensure_domain_uuid()
                url = f"{base}/api/fmc_config/v1/domain/{domain_uuid}/{p}"

        headers = {
            "X-auth-access-token": self._access_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        method_u = method.upper()

        async with httpx.AsyncClient(
            verify=self._settings.verify_ssl, timeout=self._settings.timeout
        ) as client:
            logger.info("FMC request: %s %s (params=%s)", method_u, url, params)
            resp = await client.request(
                method_u, url, headers=headers, params=params, json=json_body
            )

            # refresh token on 401
            if resp.status_code == 401:
                await self._authenticate()
                headers["X-auth-access-token"] = self._access_token or ""
                logger.info("FMC request (retry after 401): %s %s (params=%s)", method_u, url, params)
                resp = await client.request(
                    method_u, url, headers=headers, params=params, json=json_body
                )

            # ✅ Best-effort fallback for endpoints that reject expanded=true on GET-by-id
            if (
                resp.status_code == 400
                and method_u == "GET"
                and self._expanded_param_enabled(params)
                and self._looks_like_expanded_rejected(resp)
            ):
                retry_params = dict(params or {})
                retry_params.pop("expanded", None)
                logger.info(
                    "Endpoint rejected expanded=true; retrying without expanded: %s",
                    url,
                )
                resp = await client.request(
                    method_u, url, headers=headers, params=retry_params, json=json_body
                )

        if ignore_statuses and resp.status_code in ignore_statuses:
            return {}

        resp.raise_for_status()
        return resp.json() if resp.text else {}

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
        start_offset: int = 0,
        ignore_statuses: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        domain_uuid = await self.ensure_domain_uuid()
        path = f"/api/fmc_config/v1/domain/{domain_uuid}{path_suffix}"

        all_items: List[Dict[str, Any]] = []
        offset = max(0, start_offset)
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
    async def list_device_records(
        self,
        *,
        limit: int = 1000,
        hard_page_limit: int = 5,
        expanded: bool = True,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/devices/devicerecords",
            limit=limit,
            hard_page_limit=hard_page_limit,
            expanded=expanded,
            start_offset=offset,
        )

    async def list_device_ha_pairs(
        self,
        *,
        limit: int = 1000,
        hard_page_limit: int = 5,
        expanded: bool = True,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        FTD HA pairs endpoint differs by FMC version.
        Correct/documented path is under /devicehapairs/ftddevicehapairs.
        Some environments may not support it; treat 404 as empty list.
        """
        # Preferred / documented
        try:
            return await self._list_paginated(
                "/devicehapairs/ftddevicehapairs",
                limit=limit,
                expanded=expanded,
                hard_page_limit=hard_page_limit,
                start_offset=offset,
                ignore_statuses={404},
            )
        except Exception:
            # Fallback (older/alternate path used by some code samples)
            return await self._list_paginated(
                "/devices/ftddevicehapairs",
                limit=limit,
                expanded=expanded,
                hard_page_limit=hard_page_limit,
                start_offset=offset,
                ignore_statuses={404},
            )

    async def list_device_clusters(
        self,
        *,
        limit: int = 1000,
        hard_page_limit: int = 5,
        expanded: bool = True,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        FTD clusters endpoint differs by FMC version.
        Documented path is /deviceclusters/ftddevicecluster/.
        Treat 404 as empty list.
        """
        # Preferred / documented
        try:
            return await self._list_paginated(
                "/deviceclusters/ftddevicecluster",
                limit=limit,
                expanded=expanded,
                hard_page_limit=hard_page_limit,
                start_offset=offset,
                ignore_statuses={404},
            )
        except Exception:
            # Fallback (if your FMC uses a different plural form)
            return await self._list_paginated(
                "/devices/ftddeviceclusters",
                limit=limit,
                expanded=expanded,
                hard_page_limit=hard_page_limit,
                start_offset=offset,
                ignore_statuses={404},
            )

    # ---------------------------------------------------------------------
    # Backward-compatible aliases (resolver expects these names)
    # ---------------------------------------------------------------------
    async def list_devices(self, limit: int = 1000, expanded: bool = True, offset: int = 0):
        """Alias for list_device_records()."""
        return await self.list_device_records(limit=limit, expanded=expanded, offset=offset)

    async def list_ha_pairs(self, limit: int = 1000, expanded: bool = True, offset: int = 0):
        """Alias for list_device_ha_pairs()."""
        return await self.list_device_ha_pairs(limit=limit, expanded=expanded, offset=offset)

    async def list_clusters(self, limit: int = 1000, expanded: bool = True, offset: int = 0):
        """Alias for list_device_clusters()."""
        return await self.list_device_clusters(limit=limit, expanded=expanded, offset=offset)

    # ---------------------------
    async def list_policy_assignments(self) -> List[Dict[str, Any]]:
        return await self._list_paginated("/assignment/policyassignments", expanded=True, hard_page_limit=5)

    # Access policies / rules
    async def list_access_policies(
        self, *, limit: int = 1000, hard_page_limit: int = 10, expanded: bool = True
    ) -> List[Dict[str, Any]]:
        return await self._list_paginated(
            "/policy/accesspolicies", limit=limit, hard_page_limit=hard_page_limit, expanded=expanded
        )

    async def get_access_policy(self, policy_id: str, *, expanded: bool = True) -> Dict[str, Any]:
        params = {"expanded": "true"} if expanded else None
        try:
            return await self._request_json("GET", f"/policy/accesspolicies/{policy_id}", params=params)
        except httpx.HTTPStatusError as exc:
            if expanded and exc.response.status_code == 400:
                logger.info(
                    "AccessPolicy GET rejected expanded param; retrying w/out expanded: %s",
                    policy_id,
                )
                return await self._request_json("GET", f"/policy/accesspolicies/{policy_id}")
            raise

    async def get_device_record(self, device_id: str, *, expanded: bool = True) -> Dict[str, Any]:
        params = {"expanded": "true"} if expanded else None
        return await self._request_json("GET", f"/devices/devicerecords/{device_id}", params=params)

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
