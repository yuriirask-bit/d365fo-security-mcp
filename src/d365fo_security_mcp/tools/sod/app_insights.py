"""Shared App Insights query helper for KQL queries.

Handles connection string parsing, Azure AD authentication via MSAL,
and tabular response parsing. Used by login_activity.py and change_log.py.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_APP_INSIGHTS_API = "https://api.applicationinsights.io/v1/apps"
_APP_INSIGHTS_SCOPE = "https://api.applicationinsights.io/.default"


def parse_connection_string(conn_str: str) -> dict[str, str]:
    """Parse an App Insights connection string into key-value pairs."""
    parts: dict[str, str] = {}
    for segment in conn_str.split(";"):
        segment = segment.strip()
        if "=" in segment:
            key, _, value = segment.partition("=")
            parts[key.strip()] = value.strip()
    return parts


async def query_app_insights(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    connection_string: str,
    kql: str,
    *,
    timeout: float = 15.0,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run a KQL query against App Insights and return parsed rows.

    Authenticates via Azure AD using the same service principal as D365.
    Requires Monitoring Reader RBAC role on the App Insights resource.

    Returns:
        Tuple of (rows, warnings) where rows is a list of dicts
        keyed by column name from the KQL result.
    """
    warnings: list[str] = []

    parsed = parse_connection_string(connection_string)
    app_id = parsed.get("ApplicationId", "")
    if not app_id:
        warnings.append(
            "APP_INSIGHTS_CONNECTION_STRING is missing ApplicationId. "
            "Copy the full connection string from the App Insights "
            "Overview page."
        )
        return [], warnings

    try:
        import msal

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret,
        )
        token_result = app.acquire_token_for_client(scopes=[_APP_INSIGHTS_SCOPE])
        if "access_token" not in token_result:
            logger.error(
                "App Insights auth failed: %s",
                token_result.get("error_description", "unknown"),
            )
            warnings.append(
                "App Insights authentication failed. "
                "Verify the service principal has Monitoring Reader "
                "role on the App Insights resource."
            )
            return [], warnings

        headers = {"Authorization": f"Bearer {token_result['access_token']}"}
        url = f"{_APP_INSIGHTS_API}/{app_id}/query"

        async with httpx.AsyncClient() as http_client:
            response = await asyncio.wait_for(
                http_client.post(
                    url,
                    json={"query": kql},
                    headers=headers,
                ),
                timeout=timeout,
            )
            if response.status_code == 403:
                warnings.append(
                    "App Insights API returned 403. "
                    "Grant the service principal Monitoring Reader "
                    "role on the App Insights resource. See "
                    "docs/azure-ad-setup.md Step 5c."
                )
                return [], warnings

            response.raise_for_status()
            data = response.json()

        # Parse tabular response into list of dicts
        rows: list[dict[str, Any]] = []
        for table in data.get("tables", []):
            columns = [c["name"] for c in table.get("columns", [])]
            for row in table.get("rows", []):
                rows.append(dict(zip(columns, row, strict=False)))

        return rows, warnings

    except ImportError:
        warnings.append("msal package not available for App Insights auth.")
    except (
        RuntimeError,
        TimeoutError,
        OSError,
        httpx.HTTPStatusError,
    ) as exc:
        logger.debug("App Insights query failed: %s", exc)
        warnings.append("App Insights query failed.")

    return [], warnings
