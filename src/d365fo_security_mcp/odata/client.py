"""Async OData client for D365 F&O using httpx."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from d365fo_security_mcp.auth.token_manager import TokenManager
from d365fo_security_mcp.models.config import D365Profile

logger = logging.getLogger(__name__)


class ThrottlingError(Exception):
    """Raised when the D365 F&O OData endpoint continues to return HTTP 429
    after exhausting all configured retry attempts."""


class ODataClient:
    """Async OData client for D365 F&O.

    Handles authentication via TokenManager, transparent pagination, and
    retry logic for both token expiry (401) and rate-limiting (429).
    """

    DEFAULT_PAGE_SIZE = 5000

    def __init__(
        self,
        profile: D365Profile,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._profile = profile
        self._token_manager = TokenManager(profile)
        self._client: httpx.AsyncClient | None = None
        self._transport = transport

    @property
    def environment(self) -> str:
        """Return the D365 environment host (no path, no credentials)."""
        from urllib.parse import urlparse

        return urlparse(self._profile.base_url).hostname or self._profile.base_url

    async def _get_client(self) -> httpx.AsyncClient:
        """Return the shared AsyncClient, creating it on first call."""
        if self._client is None:
            token = self._token_manager.get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "OData-MaxVersion": "4.0",
                "OData-Version": "4.0",
            }
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=self._profile.request_timeout,
                transport=self._transport,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client if it is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _refresh_client(self) -> None:
        """Close the current client so a new token is fetched on the next call."""
        await self.close()

    async def _apply_rate_limit(self) -> None:
        """Pre-emptive delay between requests to avoid triggering throttling."""
        delay = self._profile.request_delay_ms / 1000
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    def _build_params(
        *,
        select: list[str] | None = None,
        filter_expr: str | None = None,
        expand: str | None = None,
        top: int | None = None,
        order_by: str | None = None,
        count: bool = False,
    ) -> dict[str, str]:
        """Construct the OData query-string parameter dictionary."""
        params: dict[str, str] = {}
        if select:
            params["$select"] = ",".join(select)
        if filter_expr:
            params["$filter"] = filter_expr
        if expand:
            params["$expand"] = expand
        if top is not None:
            params["$top"] = str(top)
        if order_by:
            params["$orderby"] = order_by
        if count:
            params["$count"] = "true"
        return params

    async def query(
        self,
        entity: str,
        *,
        select: list[str] | None = None,
        filter_expr: str | None = None,
        expand: str | None = None,
        top: int | None = None,
        order_by: str | None = None,
        count: bool = False,
    ) -> list[dict[str, Any]]:
        """Query an OData entity set and return all records.

        Handles server-side pagination via @odata.nextLink, token refresh on
        401, and retry-after back-off on 429.

        Parameters
        ----------
        entity:
            OData entity set name, e.g. ``SecurityRoles``.
        select:
            Fields to include in the response.
        filter_expr:
            OData ``$filter`` expression.
        expand:
            OData ``$expand`` expression.
        top:
            Maximum number of records to return (applied to the first page
            only; subsequent pages follow server-supplied next-links).
        order_by:
            OData ``$orderby`` expression.
        count:
            Whether to request an inline ``@odata.count``.

        Returns
        -------
        list[dict[str, Any]]
            All records collected across all pages.
        """
        base_url = f"{self._profile.odata_url}/{entity}"
        params: dict[str, str] | None = self._build_params(
            select=select,
            filter_expr=filter_expr,
            expand=expand,
            top=top,
            order_by=order_by,
            count=count,
        )

        records: list[dict[str, Any]] = []
        url: str | None = base_url
        first_page = True
        token_refreshed = False

        while url is not None:
            await self._apply_rate_limit()

            client = await self._get_client()
            request_params = params if first_page else None
            first_page = False

            throttle_attempts = 0
            while True:
                response = await client.get(url, params=request_params)

                if response.status_code == 401:
                    if token_refreshed:
                        response.raise_for_status()
                    logger.debug("Received 401; refreshing token and retrying.")
                    await self._refresh_client()
                    client = await self._get_client()
                    token_refreshed = True
                    continue

                if response.status_code == 429:
                    throttle_attempts += 1
                    if throttle_attempts > self._profile.max_retries:
                        raise ThrottlingError(
                            f"OData endpoint throttled after {self._profile.max_retries} "
                            f"retry attempts for entity '{entity}'."
                        )
                    retry_after_raw = response.headers.get("Retry-After", "5")
                    try:
                        retry_after = float(retry_after_raw)
                    except ValueError:
                        retry_after = 5.0
                    logger.warning(
                        "HTTP 429 received for entity '%s'; waiting %.1fs before retry %d/%d.",
                        entity,
                        retry_after,
                        throttle_attempts,
                        self._profile.max_retries,
                    )
                    await asyncio.sleep(retry_after)
                    continue

                if response.status_code >= 400:
                    logger.error(
                        "OData error: entity=%s status=%d body=%s",
                        entity,
                        response.status_code,
                        response.text[:500],
                    )
                    raise RuntimeError(
                        f"OData request failed for entity '{entity}' "
                        f"with HTTP {response.status_code}"
                    )

                # Successful response
                break

            data: dict[str, Any] = response.json()
            page_records: list[dict[str, Any]] = data.get("value", [])
            records.extend(page_records)

            url = data.get("@odata.nextLink")

        logger.info("Queried entity '%s'; retrieved %d record(s).", entity, len(records))
        return records

    async def query_single(
        self,
        entity: str,
        key: str,
        *,
        select: list[str] | None = None,
        expand: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve a single record by its primary key.

        Parameters
        ----------
        entity:
            OData entity set name, e.g. ``SecurityRoles``.
        key:
            The primary key value (string form, used in the URL as
            ``entity('key')``).
        select:
            Fields to include in the response.
        expand:
            OData ``$expand`` expression.

        Returns
        -------
        dict[str, Any]
            The single record returned by the endpoint.
        """
        url = f"{self._profile.odata_url}/{entity}('{key}')"
        params = self._build_params(select=select, expand=expand)

        await self._apply_rate_limit()

        token_refreshed = False
        client = await self._get_client()

        throttle_attempts = 0
        while True:
            response = await client.get(url, params=params or None)

            if response.status_code == 401:
                if token_refreshed:
                    response.raise_for_status()
                logger.debug("Received 401 on single-record fetch; refreshing token and retrying.")
                await self._refresh_client()
                client = await self._get_client()
                token_refreshed = True
                continue

            if response.status_code == 429:
                throttle_attempts += 1
                if throttle_attempts > self._profile.max_retries:
                    raise ThrottlingError(
                        f"OData endpoint throttled after {self._profile.max_retries} "
                        f"retry attempts for entity '{entity}' key '{key}'."
                    )
                retry_after_raw = response.headers.get("Retry-After", "5")
                try:
                    retry_after = float(retry_after_raw)
                except ValueError:
                    retry_after = 5.0
                logger.warning(
                    "HTTP 429 received for entity '%s' key '%s'; waiting %.1fs before retry %d/%d.",
                    entity,
                    key,
                    retry_after,
                    throttle_attempts,
                    self._profile.max_retries,
                )
                await asyncio.sleep(retry_after)
                continue

            if response.status_code >= 400:
                body_excerpt = response.text[:500]
                raise RuntimeError(
                    f"OData request failed for entity '{entity}' key '{key}' with HTTP "
                    f"{response.status_code}: {body_excerpt}"
                )

            break

        record: dict[str, Any] = response.json()
        logger.info("Queried entity '%s' for key '%s'; retrieved 1 record.", entity, key)
        return record

    async def call_action(
        self,
        action_name: str,
        entity_set: str = "DataManagementEntities",
    ) -> str:
        """Invoke a parameterless OData action and return the string result.

        The action URL follows the D365 F&O convention::

            POST {odata_url}/{entity_set}/Microsoft.Dynamics.DataEntities.{action_name}

        Parameters
        ----------
        action_name:
            Action name, e.g. ``GetApplicationVersion``.
        entity_set:
            The entity set the action is bound to.

        Returns
        -------
        str
            The string value returned by the action.
        """
        url = (
            f"{self._profile.odata_url}/{entity_set}/Microsoft.Dynamics.DataEntities.{action_name}"
        )

        await self._apply_rate_limit()

        token_refreshed = False
        client = await self._get_client()

        while True:
            response = await client.post(url, content=b"")

            if response.status_code == 401:
                if token_refreshed:
                    response.raise_for_status()
                logger.debug("Received 401 on action call; refreshing token.")
                await self._refresh_client()
                client = await self._get_client()
                token_refreshed = True
                continue

            if response.status_code >= 400:
                body_excerpt = response.text[:500]
                raise RuntimeError(
                    f"OData action '{action_name}' failed with HTTP "
                    f"{response.status_code}: {body_excerpt}"
                )

            break

        data = response.json()
        if isinstance(data, dict) and "value" in data:
            return str(data["value"])
        return str(data) if data is not None else ""
