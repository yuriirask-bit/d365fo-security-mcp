"""get_security_health_score — aggregate security posture score (0–100)."""

from __future__ import annotations

import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import DimensionScore, SecurityHealthScore, SodRuleset
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

_RATING_BANDS = [
    (90, "Excellent"),
    (70, "Good"),
    (50, "Needs Attention"),
    (0, "Critical"),
]


def _rating(score: int) -> str:
    for threshold, label in _RATING_BANDS:
        if score >= threshold:
            return label
    return "Critical"


def _dim_status(score: int, max_score: int) -> str:
    ratio = score / max_score if max_score > 0 else 0
    if ratio >= 0.8:
        return "Healthy"
    if ratio >= 0.5:
        return "Warning"
    return "Critical"


async def get_security_health_score(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    exclude_service_accounts: bool = True,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    graph_scope: str = "https://graph.microsoft.com/.default",
    app_insights_connection_string: str = "",
) -> ToolResponse:
    """Calculate aggregate security posture score (0–100)."""
    start = time.perf_counter()
    warnings: list[str] = []
    recommendations: list[str] = []

    # Fetch base data
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

    # Group assignments by user
    roles_by_user: dict[str, set[str]] = {}
    for a in all_assignments:
        uid = a.get("UserId", "")
        status = a.get("AssignmentStatus", "")
        if status not in ("Expired", "Suspended"):
            roles_by_user.setdefault(uid, set()).add(a.get("SecurityRoleIdentifier", ""))

    # --- Dimension 1: SoD Compliance (0–25) ---
    sod_score = 25
    sod_detail = "No SoD ruleset configured"
    sod_status = "Unavailable"

    if ruleset and ruleset.rules:
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
            sub_role_map = {}

        violation_count = 0
        users_with_violations = 0
        critical_violations = 0

        for user in users_data:
            uid = user.get("UserID", "")
            uname = user.get("PersonName") or user.get("UserName", uid)
            user_roles = roles_by_user.get(uid, set())
            if not user_roles:
                continue
            result = detect_for_user(uid, uname, user_roles, role_duty_map, sub_role_map, ruleset)
            if result.violation_count > 0:
                violation_count += result.violation_count
                users_with_violations += 1
                critical_violations += sum(
                    1 for v in result.violations if v.risk_level == "Critical"
                )

        if violation_count == 0:
            sod_score = 25
            sod_detail = "No SoD violations detected"
            sod_status = "Healthy"
        else:
            # Scale: more violations = lower score
            penalty = min(25, violation_count * 2 + critical_violations * 3)
            sod_score = max(0, 25 - penalty)
            sod_detail = f"{violation_count} violations across {users_with_violations} users"
            sod_status = _dim_status(sod_score, 25)
            recommendations.append(
                f"Resolve {violation_count} SoD violation(s) "
                f"affecting {users_with_violations} user(s)"
            )
            if critical_violations:
                recommendations.append(
                    f"Prioritise {critical_violations} Critical-severity violation(s)"
                )

    # --- Dimension 2: Dormant Account Risk (0–25) ---
    login_data, login_warnings = await get_login_activity(
        client,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        graph_scope=graph_scope,
        app_insights_connection_string=app_insights_connection_string,
    )
    warnings.extend(login_warnings)

    if not login_data:
        dormant_score = 25
        dormant_detail = "Login data unavailable — dimension excluded"
        dormant_status = "Unavailable"
    else:
        from datetime import datetime, timedelta, timezone

        cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
        privileged_roles = set(ruleset.privileged_roles) if ruleset else set()
        dormant_count = 0
        privileged_checked = 0

        for uid, user_roles in roles_by_user.items():
            is_privileged = bool(user_roles & privileged_roles) if privileged_roles else False
            if not is_privileged:
                continue
            privileged_checked += 1
            last_login = login_data.get(uid.lower())
            if last_login is None or last_login < cutoff_90:
                dormant_count += 1

        if privileged_checked == 0:
            dormant_score = 25
            dormant_detail = "No privileged users to check"
            dormant_status = "Healthy"
        else:
            ratio = dormant_count / privileged_checked
            dormant_score = max(0, int(25 * (1 - ratio)))
            dormant_detail = (
                f"{dormant_count} of {privileged_checked} privileged users dormant (>90 days)"
            )
            dormant_status = _dim_status(dormant_score, 25)
            if dormant_count:
                recommendations.append(f"Review {dormant_count} dormant privileged account(s)")

    # --- Dimension 3: Role Assignment Hygiene (0–25) ---
    role_counts = [len(roles) for roles in roles_by_user.values() if roles]
    if role_counts:
        avg_roles = sum(role_counts) / len(role_counts)
        excessive = sum(1 for c in role_counts if c > 10)
        # Ideal: avg < 5, no excessive
        hygiene_penalty = min(25, int(max(0, avg_roles - 5) * 3) + excessive * 2)
        hygiene_score = max(0, 25 - hygiene_penalty)
        hygiene_detail = f"Average {avg_roles:.1f} roles per user, {excessive} users with >10 roles"
        hygiene_status = _dim_status(hygiene_score, 25)
        if excessive:
            recommendations.append(f"Review {excessive} user(s) with more than 10 roles")
    else:
        hygiene_score = 25
        hygiene_detail = "No role assignments found"
        hygiene_status = "Healthy"

    # --- Dimension 4: Data Completeness (0–25) ---
    data_points = 0
    data_available = 0

    data_points += 1  # SoD ruleset
    if ruleset and ruleset.rules:
        data_available += 1

    data_points += 1  # Login data
    if login_data:
        data_available += 1

    data_points += 1  # Users
    if users_data:
        data_available += 1

    data_points += 1  # Role assignments
    if all_assignments:
        data_available += 1

    completeness_score = int(25 * data_available / data_points) if data_points else 25
    completeness_detail = f"{data_available} of {data_points} data sources available"
    completeness_status = _dim_status(completeness_score, 25)
    if data_available < data_points:
        recommendations.append(
            "Enable additional data sources for a more complete security assessment"
        )

    # --- Aggregate ---
    overall = sod_score + dormant_score + hygiene_score + completeness_score

    health = SecurityHealthScore(
        overall_score=overall,
        rating=_rating(overall),
        dimensions={
            "sod_compliance": DimensionScore(
                name="SoD Compliance",
                score=sod_score,
                status=sod_status,
                detail=sod_detail,
            ),
            "dormant_accounts": DimensionScore(
                name="Dormant Account Risk",
                score=dormant_score,
                status=dormant_status,
                detail=dormant_detail,
            ),
            "role_hygiene": DimensionScore(
                name="Role Assignment Hygiene",
                score=hygiene_score,
                status=hygiene_status,
                detail=hygiene_detail,
            ),
            "data_completeness": DimensionScore(
                name="Access Review Readiness",
                score=completeness_score,
                status=completeness_status,
                detail=completeness_detail,
            ),
        },
        recommendations=(
            recommendations
            if recommendations
            else ["No issues found — security posture is healthy"]
        ),
    )

    duration_ms = int((time.perf_counter() - start) * 1000)

    result_dict = health.model_dump()
    result_dict["service_accounts_excluded"] = service_accounts_excluded

    return ToolResponse(
        result=result_dict,
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
