"""find_dormant_privileged_accounts — users with sensitive roles and no recent login."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SYSTEM_USERS,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)
from d365fo_security_mcp.tools.sod.filters import filter_non_native_users, get_native_provider
from d365fo_security_mcp.tools.sod.login_activity import get_login_activity


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _get_privileged_role_ids(ruleset: SodRuleset | None) -> set[str]:
    """Determine which roles are privileged.

    Uses curated list from ruleset if available, otherwise falls back
    to roles participating in SoD rules + known admin roles.
    """
    if ruleset and ruleset.privileged_roles:
        return set(ruleset.privileged_roles)

    # Fallback: admin patterns + SoD-participating roles
    privileged: set[str] = {
        "-SYSADMIN-",
        "SYSTEMADMINISTRATOR",
        "SECURITYADMINISTRATOR",
    }
    if ruleset:
        # Collect all role→duty mappings would require OData.
        # At this level we can only flag admin roles as privileged.
        # The detection will also check if user's roles have SoD-relevant duties.
        pass

    return privileged


async def find_dormant_privileged_accounts(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    days: int = 90,
    exclude_service_accounts: bool = True,
    redact_pii: bool = False,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    graph_scope: str = "https://graph.microsoft.com/.default",
    app_insights_connection_string: str = "",
) -> ToolResponse:
    """Find privileged users who haven't logged in within the threshold."""
    start = time.perf_counter()
    warnings: list[str] = []

    privileged_roles = _get_privileged_role_ids(ruleset)

    # Fetch users and assignments
    users_data = await client.query(
        ENTITY_SYSTEM_USERS,
        filter_expr="Enabled eq true",
        select=["UserID", "UserName", "PersonName", "Email", "Enabled", "NetworkDomain"],
    )

    service_accounts_excluded = 0
    if exclude_service_accounts:
        native_provider, provider_warnings = await get_native_provider(client)
        warnings.extend(provider_warnings)
        users_data, service_accounts_excluded = filter_non_native_users(users_data, native_provider)

    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )

    # If ruleset has rules but no curated privileged_roles, also treat
    # roles that participate in SoD rules as privileged (fallback)
    if ruleset and not ruleset.privileged_roles and ruleset.rules:
        duties_data = await client.query(
            ENTITY_SECURITY_DUTIES,
            select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
        )
        sod_duties: set[str] = set()
        for rule in ruleset.rules:
            sod_duties.update(rule.duty_group_a.duties)
            sod_duties.update(rule.duty_group_b.duties)

        for row in duties_data:
            if row.get("SecurityDutyIdentifier", "") in sod_duties:
                privileged_roles.add(row.get("SecurityRoleIdentifier", ""))

    # Group assignments by user, filter to privileged roles
    privileged_users: dict[str, list[str]] = {}
    for a in all_assignments:
        uid = a.get("UserId", "")
        role_id = a.get("SecurityRoleIdentifier", "")
        status = a.get("AssignmentStatus", "")
        if status not in ("Expired", "Suspended") and role_id in privileged_roles:
            privileged_users.setdefault(uid, []).append(role_id)

    if not privileged_users:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ToolResponse(
            result={
                "dormant_count": 0,
                "privileged_users_checked": 0,
                "threshold_days": days,
                "service_accounts_excluded": service_accounts_excluded,
                "users": [],
                "message": "No users with privileged roles found.",
            },
            metadata=ResponseMetadata(
                provider="sod",
                environment=client.environment,
                duration_ms=duration_ms,
                currency="",
            ),
            warnings=warnings,
        )

    # Fetch login activity from all sources
    login_data, login_warnings = await get_login_activity(
        client,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        graph_scope=graph_scope,
        app_insights_connection_string=app_insights_connection_string,
    )
    warnings.extend(login_warnings)

    # Build user lookup
    user_lookup: dict[str, dict[str, str]] = {}
    for u in users_data:
        uid = u.get("UserID", "")
        user_lookup[uid] = {
            "name": u.get("PersonName") or u.get("UserName", uid),
            "email": u.get("Email", ""),
        }

    # Check each privileged user against threshold
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    dormant_users: list[dict[str, Any]] = []
    login_data_available = bool(login_data)

    for uid, roles in privileged_users.items():
        user_info = user_lookup.get(uid, {"name": uid, "email": ""})

        # Try matching login data by user_id (lowercased), email
        last_login: datetime | None = None
        for key in [uid.lower(), user_info["email"].lower()]:
            if key and key in login_data:
                ts = login_data[key]
                if last_login is None or ts > last_login:
                    last_login = ts

        is_dormant = last_login is None or last_login < cutoff

        if is_dormant:
            days_since = (datetime.now(timezone.utc) - last_login).days if last_login else None
            dormant_users.append(
                {
                    "user_id": uid,
                    "user_name": _redact(user_info["name"], redact_pii),
                    "privileged_roles": sorted(roles),
                    "last_login": last_login.isoformat() if last_login else None,
                    "days_since_login": days_since,
                    "login_data_available": last_login is not None,
                }
            )

    # Sort by days_since_login descending (most dormant first), None last
    dormant_users.sort(
        key=lambda u: u["days_since_login"] if u["days_since_login"] is not None else 999999,
        reverse=True,
    )

    if not login_data_available:
        warnings.append(
            "Login data unavailable from both sources. "
            "All privileged users listed based on role assignments only."
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "dormant_count": len(dormant_users),
            "privileged_users_checked": len(privileged_users),
            "threshold_days": days,
            "service_accounts_excluded": service_accounts_excluded,
            "users": dormant_users,
        },
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
