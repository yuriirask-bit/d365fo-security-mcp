"""run_user_access_review — compliance-ready user access review list."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SECURITY_SUB_ROLES,
    ENTITY_SYSTEM_USERS,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)
from d365fo_security_mcp.tools.sod.detector import (
    build_role_duty_map,
    build_sub_role_map,
    detect_for_user,
)
from d365fo_security_mcp.tools.sod.filters import filter_non_native_users, get_native_provider
from d365fo_security_mcp.tools.sod.login_activity import get_login_activity


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def run_user_access_review(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    include_disabled: bool = False,
    exclude_service_accounts: bool = True,
    sod_only: bool = False,
    redact_pii: bool = False,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    graph_scope: str = "https://graph.microsoft.com/.default",
    app_insights_connection_string: str = "",
) -> ToolResponse:
    """Produce a compliance-ready user access review list."""
    start = time.perf_counter()
    warnings: list[str] = []

    # Fetch users
    filter_expr = "" if include_disabled else "Enabled eq true"
    users_data = await client.query(
        ENTITY_SYSTEM_USERS,
        filter_expr=filter_expr if filter_expr else None,
        select=["UserID", "UserName", "PersonName", "Email", "Enabled", "NetworkDomain"],
    )

    service_accounts_excluded = 0
    if exclude_service_accounts:
        native_provider, provider_warnings = await get_native_provider(client)
        warnings.extend(provider_warnings)
        users_data, service_accounts_excluded = filter_non_native_users(users_data, native_provider)

    # Fetch role assignments and duties for SoD check
    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )

    # SoD detection setup
    has_ruleset = ruleset is not None and bool(ruleset.rules)
    role_duty_map: dict[str, list[str]] = {}
    sub_role_map: dict[str, list[str]] = {}

    if has_ruleset:
        duties_data = await client.query(
            ENTITY_SECURITY_DUTIES,
            select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
        )
        role_duty_map = build_role_duty_map(duties_data)
        try:
            sub_roles_data = await client.query(
                ENTITY_SECURITY_SUB_ROLES,
                select=["SecurityRoleIdentifier", "SecuritySubRoleIdentifier"],
            )
            sub_role_map = build_sub_role_map(sub_roles_data)
        except (RuntimeError, TimeoutError, OSError):
            warnings.append("Sub-role data unavailable.")
    else:
        warnings.append("No SoD ruleset configured; SoD flags not available.")

    # Group assignments by user
    assignments_by_user: dict[str, list[dict[str, str]]] = {}
    role_ids_by_user: dict[str, set[str]] = {}
    for a in all_assignments:
        uid = a.get("UserId", "")
        status = a.get("AssignmentStatus", "")
        if status not in ("Expired", "Suspended"):
            assignments_by_user.setdefault(uid, []).append(
                {
                    "role_id": a.get("SecurityRoleIdentifier", ""),
                    "role_name": a.get("SecurityRoleName", ""),
                }
            )
            role_ids_by_user.setdefault(uid, set()).add(a.get("SecurityRoleIdentifier", ""))

    # Fetch login data from all sources
    login_data, login_warnings = await get_login_activity(
        client,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        graph_scope=graph_scope,
        app_insights_connection_string=app_insights_connection_string,
    )
    warnings.extend(login_warnings)

    # Build review list
    review_list: list[dict[str, Any]] = []
    for user in users_data:
        uid = user.get("UserID", "")
        uname = user.get("PersonName") or user.get("UserName", uid)
        uemail = user.get("Email", "")
        enabled = user.get("Enabled", True)
        user_roles = assignments_by_user.get(uid, [])
        user_role_ids = role_ids_by_user.get(uid, set())

        # SoD check
        has_sod_violations = False
        sod_violation_count = 0
        if has_ruleset and user_role_ids:
            sod_result = detect_for_user(
                user_id=uid,
                user_name=uname,
                assigned_role_ids=user_role_ids,
                role_duty_map=role_duty_map,
                sub_role_map=sub_role_map,
                ruleset=ruleset,  # type: ignore[arg-type]
            )
            has_sod_violations = sod_result.violation_count > 0
            sod_violation_count = sod_result.violation_count

        if sod_only and not has_sod_violations:
            continue

        # Login data lookup
        last_login_str: str | None = None
        for key in [uid.lower(), uemail.lower()]:
            if key and key in login_data:
                last_login_str = login_data[key].isoformat()
                break

        review_list.append(
            {
                "user_id": uid,
                "user_name": _redact(uname, redact_pii),
                "email": _redact(uemail, redact_pii),
                "enabled": enabled,
                "role_count": len(user_roles),
                "roles": [r["role_name"] for r in user_roles],
                "last_login": last_login_str,
                "has_sod_violations": has_sod_violations,
                "sod_violation_count": sod_violation_count,
            }
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "total_users": len(review_list),
            "users_with_sod_violations": sum(1 for u in review_list if u["has_sod_violations"]),
            "service_accounts_excluded": service_accounts_excluded,
            "users": review_list,
        },
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
