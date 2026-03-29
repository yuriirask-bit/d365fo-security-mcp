"""get_org_security_map — map users to organisation-scoped role assignments."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_USER_ROLE_ORGS,
    ENTITY_SYSTEM_USERS,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)
from d365fo_security_mcp.tools.sod.filters import filter_non_native_users, get_native_provider


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def get_org_security_map(
    client: ODataClient,
    *,
    user_id: str = "",
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> ToolResponse:
    """Map users to their organisation-scoped role assignments.

    Shows which users can operate in which legal entities. Users with
    only globally-scoped roles are included and marked accordingly.
    """
    start = time.perf_counter()
    warnings: list[str] = []
    service_accounts_excluded = 0

    # Fetch users
    if user_id:
        users_data = await client.query(
            ENTITY_SYSTEM_USERS,
            filter_expr=f"UserID eq '{escape_odata_string(user_id)}'",
            select=["UserID", "UserName", "PersonName", "Enabled", "NetworkDomain"],
        )
        if not users_data:
            return ToolResponse(
                result=None,
                metadata=ResponseMetadata(
                    provider="sod",
                    environment=client.environment,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    currency="",
                ),
                warnings=[f"User '{user_id}' not found."],
            )
    else:
        users_data = await client.query(
            ENTITY_SYSTEM_USERS,
            filter_expr="Enabled eq true",
            select=["UserID", "UserName", "PersonName", "Enabled", "NetworkDomain"],
        )

        if exclude_service_accounts:
            native_provider, provider_warnings = await get_native_provider(client)
            warnings.extend(provider_warnings)
            users_data, service_accounts_excluded = filter_non_native_users(
                users_data, native_provider
            )

    # Fetch org-scoped assignments
    try:
        org_data: list[dict[str, Any]] = await client.query(
            ENTITY_SECURITY_USER_ROLE_ORGS,
        )
    except (RuntimeError, TimeoutError, OSError):
        org_data = []
        warnings.append(
            "Organisation-scoped role data unavailable. "
            "The SecurityUserRoleOrganizations entity may not be accessible."
        )

    # Fetch global role assignments for context
    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )

    # Group org assignments by user
    org_by_user: dict[str, list[dict[str, Any]]] = {}
    for row in org_data:
        uid = row.get("UserId", "")
        org_by_user.setdefault(uid, []).append(row)

    # Group global assignments by user
    global_by_user: dict[str, list[dict[str, str]]] = {}
    for a in all_assignments:
        uid = a.get("UserId", "")
        status = a.get("AssignmentStatus", "")
        if status not in ("Expired", "Suspended"):
            global_by_user.setdefault(uid, []).append(
                {
                    "role_id": a.get("SecurityRoleIdentifier", ""),
                    "role_name": a.get("SecurityRoleName", ""),
                }
            )

    # Build per-user map
    users_list: list[dict[str, Any]] = []
    for user in users_data:
        uid = user.get("UserID", "")
        uname = user.get("PersonName") or user.get("UserName", uid)
        user_org_assignments = org_by_user.get(uid, [])
        user_global_roles = global_by_user.get(uid, [])

        # Group org assignments by organisation
        orgs: dict[str, list[dict[str, str]]] = {}
        for oa in user_org_assignments:
            org_name = oa.get("InternalOrganizationName", "") or oa.get("dataAreaId", "unknown")
            orgs.setdefault(org_name, []).append(
                {
                    "role_id": oa.get("SecurityRoleIdentifier", ""),
                    "role_name": oa.get("SecurityRoleName", ""),
                }
            )

        users_list.append(
            {
                "user_id": uid,
                "user_name": _redact(uname, redact_pii),
                "global_roles": user_global_roles,
                "organisation_roles": orgs if orgs else None,
                "scope": "organisation" if orgs else "global_only",
            }
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "total_users": len(users_list),
            "users_with_org_scope": sum(1 for u in users_list if u["scope"] == "organisation"),
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
