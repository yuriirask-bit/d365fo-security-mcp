"""get_all_user_role_assignments — complete user-role assignment matrix."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.constants import (
    ENTITY_SYSTEM_USERS,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)
from d365fo_security_mcp.tools.sod.filters import filter_non_native_users, get_native_provider


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def get_all_user_role_assignments(
    client: ODataClient,
    *,
    active_only: bool = False,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> ToolResponse:
    """Return the complete user-role assignment matrix.

    Args:
        client: OData client for D365 queries.
        active_only: If true, exclude expired/suspended assignments.
        redact_pii: Hash user names in output.

    Returns:
        ToolResponse with every user and their role assignments.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    users_data = await client.query(
        ENTITY_SYSTEM_USERS,
        filter_expr="Enabled eq true",
        select=["UserID", "UserName", "PersonName", "Enabled", "NetworkDomain"],
    )

    service_accounts_excluded = 0
    if exclude_service_accounts:
        native_provider, provider_warnings = await get_native_provider(client)
        warnings.extend(provider_warnings)
        users_data, service_accounts_excluded = filter_non_native_users(users_data, native_provider)

    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )

    # Group assignments by user
    assignments_by_user: dict[str, list[dict[str, Any]]] = {}
    for a in all_assignments:
        uid = a.get("UserId", "")
        status = a.get("AssignmentStatus", "")
        if active_only and status in ("Expired", "Suspended"):
            continue
        assignments_by_user.setdefault(uid, []).append(
            {
                "role_id": a.get("SecurityRoleIdentifier", ""),
                "role_name": a.get("SecurityRoleName", ""),
                "assignment_status": status,
                "assignment_mode": a.get("AssignmentMode", ""),
            }
        )

    # Build per-user result
    users_list: list[dict[str, Any]] = []
    for user in users_data:
        uid = user.get("UserID", "")
        uname = user.get("PersonName") or user.get("UserName", uid)
        user_assignments = assignments_by_user.get(uid, [])

        users_list.append(
            {
                "user_id": uid,
                "user_name": _redact(uname, redact_pii),
                "role_count": len(user_assignments),
                "roles": user_assignments,
            }
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "total_users": len(users_list),
            "total_assignments": sum(u["role_count"] for u in users_list),
            "service_accounts_excluded": service_accounts_excluded,
            "users": users_list,
        },
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
