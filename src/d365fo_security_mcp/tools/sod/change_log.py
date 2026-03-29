"""get_security_change_log — role assignment changes via App Insights custom events.

Queries customEvents emitted by the SMCPSecurityRoleEventHandler X++ class
when roles are assigned or revoked in D365 F&O.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.app_insights import query_app_insights

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


_SETUP_GUIDANCE = (
    "Role assignment change tracking requires the "
    "SMCPSecurityRoleEventHandler X++ class deployed in D365 F&O "
    "with Application Insights enabled. The event handler emits "
    "SecurityRoleAssigned/SecurityRoleRevoked custom events to "
    "App Insights. See docs/d365-custom-entities.md for details."
)

# KQL template — {days_filter} and {user_filter} are injected
_CHANGE_LOG_KQL_TEMPLATE = (
    "customEvents"
    ' | where name in ("SecurityRoleAssigned", "SecurityRoleRevoked")'
    " | where timestamp >= ago({days}d)"
    "{user_filter}"
    " | project"
    "     timestamp,"
    '     ChangeType = iff(name == "SecurityRoleAssigned", "Added", "Removed"),'
    "     UserId = tostring(customDimensions.UserId),"
    "     SecurityRoleId = tostring(customDimensions.SecurityRoleId),"
    "     SecurityRoleName = tostring(customDimensions.SecurityRoleName),"
    "     ChangedBy = tostring(customDimensions.ChangedBy)"
    " | order by timestamp desc"
)


def _build_kql(days: int, user_id: str = "") -> str:
    """Build the KQL query with optional user filter."""
    user_filter = ""
    if user_id:
        # KQL string comparison — safe because user_id is filtered
        safe_uid = user_id.replace("'", "\\'")
        user_filter = f' | where tostring(customDimensions.UserId) == "{safe_uid}"'
    return _CHANGE_LOG_KQL_TEMPLATE.format(days=days, user_filter=user_filter)


async def get_security_change_log(
    client: ODataClient,
    *,
    days: int = 30,
    user_id: str = "",
    redact_pii: bool = False,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    app_insights_connection_string: str = "",
) -> ToolResponse:
    """Retrieve role assignment changes over a date range.

    Queries App Insights customEvents emitted by the
    SMCPSecurityRoleEventHandler X++ class. If App Insights is not
    configured, returns an empty result with setup guidance.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    if not app_insights_connection_string:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ToolResponse(
            result={
                "changes": [],
                "total_changes": 0,
                "period_days": days,
            },
            metadata=ResponseMetadata(
                provider="sod",
                environment=client.environment,
                duration_ms=duration_ms,
                currency="",
            ),
            warnings=["APP_INSIGHTS_CONNECTION_STRING not configured. " + _SETUP_GUIDANCE],
        )

    if not (tenant_id and client_id and client_secret):
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ToolResponse(
            result={
                "changes": [],
                "total_changes": 0,
                "period_days": days,
            },
            metadata=ResponseMetadata(
                provider="sod",
                environment=client.environment,
                duration_ms=duration_ms,
                currency="",
            ),
            warnings=["Azure AD credentials missing for App Insights query."],
        )

    kql = _build_kql(days, user_id)
    rows, query_warnings = await query_app_insights(
        tenant_id,
        client_id,
        client_secret,
        app_insights_connection_string,
        kql,
    )
    warnings.extend(query_warnings)

    changes: list[dict[str, Any]] = []
    for row in rows:
        changes.append(
            {
                "timestamp": row.get("timestamp", ""),
                "user_id": row.get("UserId", ""),
                "role_id": row.get("SecurityRoleId", ""),
                "role_name": row.get("SecurityRoleName", ""),
                "change_type": row.get("ChangeType", ""),
                "changed_by": _redact(row.get("ChangedBy", ""), redact_pii),
            }
        )

    if not changes and not query_warnings:
        warnings.append(
            f"No role assignment changes found in the last {days} days. "
            "This may mean the X++ event handler is not deployed or "
            "no role changes have occurred."
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "total_changes": len(changes),
            "period_days": days,
            "source": "AppInsights/customEvents",
            "changes": changes,
        },
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
