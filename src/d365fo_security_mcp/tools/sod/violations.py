"""detect_sod_violations — run SoD conflict rules against users."""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset, UserSodResult
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
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

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def detect_sod_violations(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    user_id: str = "",
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> ToolResponse:
    """Run SoD conflict rules against all enabled users or a single user.

    Args:
        client: OData client for D365 queries.
        ruleset: The loaded SoD conflict ruleset. None if not configured.
        user_id: Scope to a single user. Empty = all enabled users.
        redact_pii: Hash user names in output.

    Returns:
        ToolResponse with violations grouped by user.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    if ruleset is None:
        return ToolResponse(
            result=None,
            metadata=ResponseMetadata(
                provider="sod",
                environment=client.environment,
                duration_ms=0,
                currency="",
            ),
            warnings=[
                "No SoD ruleset configured. "
                "Set SOD_RULES_FILE to the path of your SoD conflict "
                "ruleset JSON file."
            ],
        )

    # Query security data in bulk
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

    # Service account filtering
    service_accounts_excluded = 0
    if not user_id and exclude_service_accounts:
        native_provider, provider_warnings = await get_native_provider(client)
        warnings.extend(provider_warnings)
        users_data, service_accounts_excluded = filter_non_native_users(users_data, native_provider)

    # Query role assignments, duties, and sub-roles
    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )
    duties_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_DUTIES,
        select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
    )

    # Sub-roles — graceful degradation if entity unavailable
    try:
        sub_roles_data: list[dict[str, Any]] = await client.query(
            ENTITY_SECURITY_SUB_ROLES,
            select=["SecurityRoleIdentifier", "SecuritySubRoleIdentifier"],
        )
    except (RuntimeError, TimeoutError, OSError):
        logger.debug("SecuritySubRoles query failed; proceeding without sub-roles")
        sub_roles_data = []
        warnings.append(
            "Sub-role data unavailable; SoD detection uses directly assigned roles only."
        )

    # Build lookup maps
    role_duty_map = build_role_duty_map(duties_data)
    sub_role_map = build_sub_role_map(sub_roles_data)

    # Group assignments by user
    assignments_by_user: dict[str, set[str]] = {}
    for assignment in all_assignments:
        uid = assignment.get("UserId", "")
        role_id = assignment.get("SecurityRoleIdentifier", "")
        status = assignment.get("AssignmentStatus", "")
        if uid and role_id and status not in ("Expired", "Suspended"):
            assignments_by_user.setdefault(uid, set()).add(role_id)

    # Run detection per user
    results: list[UserSodResult] = []
    for user in users_data:
        uid = user.get("UserID", "")
        uname = user.get("PersonName") or user.get("UserName", uid)
        user_roles = assignments_by_user.get(uid, set())

        if not user_roles:
            continue

        result = detect_for_user(
            user_id=uid,
            user_name=_redact(uname, redact_pii),
            assigned_role_ids=user_roles,
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=ruleset,
        )

        if result.violation_count > 0:
            results.append(result)

    # Sort by risk score descending
    results.sort(key=lambda r: r.risk_score, reverse=True)

    total_violations = sum(r.violation_count for r in results)
    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result={
            "total_violations": total_violations,
            "users_scanned": len(users_data),
            "service_accounts_excluded": service_accounts_excluded,
            "users_with_violations": len(results),
            "ruleset_version": ruleset.metadata.version,
            "rules_evaluated": len(ruleset.rules),
            "users": [r.model_dump() for r in results],
        },
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
