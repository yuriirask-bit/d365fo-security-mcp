"""Login activity retrieval — three sources queried in parallel.

Sources (all optional, most recent timestamp wins):
1. Azure Application Insights pageViews telemetry (D365 interactive sessions)
2. DatabaseLogs entity (if Database Logging enabled for SysUserLog)
3. Microsoft Graph signInActivity (requires AuditLog.Read.All)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime
from typing import Any

import httpx

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.app_insights import query_app_insights

logger = logging.getLogger(__name__)

_DATABASE_LOGS_ENTITY = "DatabaseLogs"

# KQL: summarise per session first, then per user to get most recent login.
# D365 F&O populates user_Id (D365 user ID) not user_AuthenticatedId.
_LOGIN_KQL = (
    "pageViews"
    " | where isnotempty(user_Id)"
    " | summarize LoginTime=min(timestamp) by user_Id, session_Id"
    " | summarize LastLogin=max(LoginTime) by user_Id"
)


async def _fetch_app_insights_logins(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    connection_string: str,
) -> tuple[dict[str, datetime], list[str]]:
    """Fetch last-login per user from App Insights pageViews telemetry."""
    rows, warnings = await query_app_insights(
        tenant_id,
        client_id,
        client_secret,
        connection_string,
        _LOGIN_KQL,
    )

    result: dict[str, datetime] = {}
    for row in rows:
        uid = (row.get("user_Id") or "").lower()
        ts_str = row.get("LastLogin") or ""
        if uid and ts_str:
            with contextlib.suppress(ValueError, TypeError):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if uid not in result or ts > result[uid]:
                    result[uid] = ts

    if result:
        logger.info(
            "Loaded login data from App Insights pageViews: %d users",
            len(result),
        )

    return result, warnings


async def _fetch_database_log_logins(
    client: ODataClient,
) -> tuple[dict[str, datetime], list[str]]:
    """Fetch login records from DatabaseLogs (if DB logging enabled for SysUserLog)."""
    warnings: list[str] = []
    result: dict[str, datetime] = {}

    try:
        logs: list[dict[str, Any]] = await asyncio.wait_for(
            client.query(
                _DATABASE_LOGS_ENTITY,
            ),
            timeout=15.0,
        )
        # Filter to SysUserLog table entries only
        for row in logs:
            table = row.get("TableName", "")
            if "SysUserLog" not in table and "UserLog" not in table:
                continue
            uid = (row.get("NewValue") or row.get("OldValue") or "").lower()
            ts_str = row.get("CreatedDateTime", "")
            if uid and ts_str:
                with contextlib.suppress(ValueError, TypeError):
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if uid not in result or ts > result[uid]:
                        result[uid] = ts
        if result:
            logger.info("Loaded login data from DatabaseLogs: %d users", len(result))
    except (RuntimeError, TimeoutError, OSError):
        logger.debug("DatabaseLogs entity unavailable for login data")

    return result, warnings


async def _fetch_graph_sign_in_data(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    graph_scope: str = "https://graph.microsoft.com/.default",
) -> tuple[dict[str, datetime], list[str]]:
    """Fetch last sign-in timestamps from Microsoft Graph signInActivity."""
    warnings: list[str] = []
    result: dict[str, datetime] = {}

    try:
        import msal

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id, authority=authority, client_credential=client_secret
        )
        token_result = app.acquire_token_for_client(scopes=[graph_scope])
        if "access_token" not in token_result:
            logger.error(
                "Graph auth failed for sign-in activity: %s",
                token_result.get("error_description", "unknown"),
            )
            warnings.append(
                "Graph authentication failed for sign-in activity. "
                "Verify app registration credentials."
            )
            return result, warnings

        headers = {"Authorization": f"Bearer {token_result['access_token']}"}
        url: str | None = (
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,userPrincipalName,mail,mailNickname,signInActivity"
        )

        async with httpx.AsyncClient() as http_client:
            while url:
                response = await http_client.get(url, headers=headers)
                if response.status_code == 403:
                    warnings.append(
                        "Graph signInActivity returned 403. "
                        "This requires both AuditLog.Read.All "
                        "permission AND an Entra ID P1/P2 "
                        "(Premium) licence on the tenant."
                    )
                    return result, warnings

                response.raise_for_status()
                data = response.json()

                for user in data.get("value", []):
                    sign_in = user.get("signInActivity") or {}
                    last_sign_in_str = sign_in.get("lastSignInDateTime", "")
                    last_non_interactive = sign_in.get("lastNonInteractiveSignInDateTime", "")

                    timestamps: list[datetime] = []
                    for ts_str in (last_sign_in_str, last_non_interactive):
                        if ts_str:
                            with contextlib.suppress(ValueError, TypeError):
                                timestamps.append(
                                    datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                )

                    if not timestamps:
                        continue

                    latest = max(timestamps)

                    # Register under multiple keys (lowercased) for matching
                    upn = (user.get("userPrincipalName") or "").lower()
                    mail = (user.get("mail") or "").lower()
                    nickname = (user.get("mailNickname") or "").lower()
                    entra_id = (user.get("id") or "").lower()

                    for key in {upn, mail, nickname, entra_id} - {""}:
                        if key not in result or latest > result[key]:
                            result[key] = latest
                    if upn and "@" in upn:
                        local = upn.split("@")[0]
                        if local and (local not in result or latest > result[local]):
                            result[local] = latest

                url = data.get("@odata.nextLink")

        if result:
            logger.info("Loaded Graph sign-in data: %d users", len(result))

    except ImportError:
        warnings.append("msal package not available for Graph sign-in data.")
    except (RuntimeError, TimeoutError, OSError):
        logger.debug("Graph sign-in data unavailable", exc_info=True)
        warnings.append("Graph sign-in activity data unavailable.")

    return result, warnings


async def get_login_activity(
    client: ODataClient,
    *,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    graph_scope: str = "https://graph.microsoft.com/.default",
    app_insights_connection_string: str = "",
) -> tuple[dict[str, datetime], list[str]]:
    """Fetch login activity from all available sources in parallel.

    Three sources (all optional, most recent timestamp wins):
    1. Azure Application Insights pageViews (D365 interactive sessions)
    2. DatabaseLogs entity (if DB logging enabled for SysUserLog)
    3. Microsoft Graph signInActivity

    Returns a merged mapping of user_key (lowercased) → most_recent_login.
    """
    warnings: list[str] = []

    # Build task list — App Insights needs connection string + Azure AD creds
    if app_insights_connection_string and tenant_id and client_id and client_secret:
        app_insights_task = _fetch_app_insights_logins(
            tenant_id,
            client_id,
            client_secret,
            app_insights_connection_string,
        )
    else:

        async def _no_app_insights() -> tuple[dict[str, datetime], list[str]]:
            if app_insights_connection_string:
                return {}, [
                    "App Insights connection string configured but Azure AD credentials missing."
                ]
            return {}, []

        app_insights_task = _no_app_insights()

    d365_dblog_task = _fetch_database_log_logins(client)

    if tenant_id and client_id and client_secret:
        graph_task = _fetch_graph_sign_in_data(tenant_id, client_id, client_secret, graph_scope)
    else:

        async def _empty() -> tuple[dict[str, datetime], list[str]]:
            return {}, ["Graph credentials not configured; skipping sign-in data."]

        graph_task = _empty()

    # Run all three in parallel
    (
        (app_insights_data, app_insights_warnings),
        (dblog_data, dblog_warnings),
        (graph_data, graph_warnings),
    ) = await asyncio.gather(app_insights_task, d365_dblog_task, graph_task)

    warnings.extend(app_insights_warnings)
    warnings.extend(dblog_warnings)
    warnings.extend(graph_warnings)

    # Merge: take latest timestamp per key across all sources
    merged: dict[str, datetime] = {}
    for source_data in (app_insights_data, dblog_data, graph_data):
        for key, ts in source_data.items():
            if key not in merged or ts > merged[key]:
                merged[key] = ts

    sources_used = []
    if app_insights_data:
        sources_used.append("App Insights pageViews")
    if dblog_data:
        sources_used.append("DatabaseLogs")
    if graph_data:
        sources_used.append("Graph signInActivity")

    if not merged:
        warnings.append(
            "No login activity data available from any source. "
            "Configure at least one: App Insights "
            "(APP_INSIGHTS_CONNECTION_STRING), "
            "Database Logging for SysUserLog, or Graph "
            "AuditLog.Read.All permission."
        )

    return merged, warnings
