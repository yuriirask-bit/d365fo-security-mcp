from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SECURITY_ROLES,
    ENTITY_SECURITY_SUB_ROLES,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)
from d365fo_security_mcp.tools.sod.detector import (
    build_role_duty_map,
    build_sub_role_map,
    detect_for_user,
)

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if should_redact:
        return hashlib.sha256(value.encode()).hexdigest()[:12]
    return value


async def what_if_analysis(
    client: ODataClient,
    tier_config: LicenceTierConfig,
    user_id: str,
    *,
    add_roles: list[str] | None = None,
    remove_roles: list[str] | None = None,
    ruleset: SodRuleset | None = None,
    redact_pii: bool = False,
) -> ToolResponse:
    """Simulate role changes and show projected licence tier and cost delta."""
    start = time.monotonic()
    add_roles = add_roles or []
    remove_roles = remove_roles or []
    warnings: list[str] = []

    # Query all SecurityRoles and build lookup
    raw_roles: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_ROLES,
        select=["SecurityRoleIdentifier", "SecurityRoleName", "UserLicenseType"],
    )
    role_lookup: dict[str, tuple[str, str]] = {
        r["SecurityRoleIdentifier"]: (
            r.get("SecurityRoleName", ""),
            r.get("UserLicenseType", "None"),
        )
        for r in raw_roles
    }

    # Validate add_roles
    for role_id in add_roles:
        if role_id not in role_lookup:
            warnings.append(f"Unrecognised role: {role_id}")

    # Query user's current role assignments
    assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
        filter_expr=f"UserId eq '{escape_odata_string(user_id)}'",
    )

    current_roles: list[str] = [
        a.get("SecurityRoleIdentifier", "")
        for a in assignments
        if a.get("AssignmentStatus", "Active") not in ("Expired", "Suspended")
    ]

    # Determine current tier
    current_licence_types = [role_lookup[r][1] for r in current_roles if r in role_lookup]
    current_tier = tier_config.highest_tier(current_licence_types)

    # Apply changes
    projected_role_set = (set(current_roles) - set(remove_roles)) | {
        r for r in add_roles if r in role_lookup
    }
    projected_roles: list[str] = sorted(projected_role_set)

    # Determine projected tier
    projected_licence_types = [role_lookup[r][1] for r in projected_roles if r in role_lookup]
    projected_tier = tier_config.highest_tier(projected_licence_types)

    # Cost deltas
    monthly_delta = float(projected_tier.monthly_cost - current_tier.monthly_cost)
    annual_delta = round(monthly_delta * 12, 2)

    # SoD projection
    sod_impact = None
    if ruleset is not None:
        # Query duty and sub-role data for projection
        duties_data = await client.query(
            ENTITY_SECURITY_DUTIES,
            select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
        )
        try:
            sub_roles_data = await client.query(
                ENTITY_SECURITY_SUB_ROLES,
                select=["SecurityRoleIdentifier", "SecuritySubRoleIdentifier"],
            )
        except (RuntimeError, TimeoutError, OSError):
            sub_roles_data = []
            warnings.append("Sub-role data unavailable for SoD projection.")

        role_duty_map = build_role_duty_map(duties_data)
        sub_role_map = build_sub_role_map(sub_roles_data)

        # Detect current violations
        current_result = detect_for_user(
            user_id=user_id,
            user_name="",
            assigned_role_ids=set(current_roles),
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=ruleset,
        )
        # Detect projected violations
        projected_result = detect_for_user(
            user_id=user_id,
            user_name="",
            assigned_role_ids=set(projected_roles),
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=ruleset,
        )

        # Diff by rule_id
        current_rule_ids = {v.rule_id for v in current_result.violations}
        projected_rule_ids = {v.rule_id for v in projected_result.violations}

        new_violations = [
            v.model_dump() for v in projected_result.violations if v.rule_id not in current_rule_ids
        ]
        resolved_violations = [
            v.model_dump() for v in current_result.violations if v.rule_id not in projected_rule_ids
        ]

        sod_impact = {
            "current_violations": current_result.violation_count,
            "projected_violations": projected_result.violation_count,
            "net_change": projected_result.violation_count - current_result.violation_count,
            "new_violations": new_violations,
            "resolved_violations": resolved_violations,
        }
    else:
        warnings.append("SoD projection unavailable \u2014 no ruleset configured.")

    result = {
        "user_id": _redact(user_id, redact_pii),
        "current_tier": {
            "name": current_tier.name,
            "display_name": current_tier.display_name,
            "monthly_cost": float(current_tier.monthly_cost),
        },
        "projected_tier": {
            "name": projected_tier.name,
            "display_name": projected_tier.display_name,
            "monthly_cost": float(projected_tier.monthly_cost),
        },
        "monthly_delta": round(monthly_delta, 2),
        "annual_delta": annual_delta,
        "current_roles": sorted(current_roles),
        "projected_roles": projected_roles,
    }

    if sod_impact is not None:
        result["sod_impact"] = sod_impact

    metadata = ResponseMetadata(
        duration_ms=int((time.monotonic() - start) * 1000),
        environment=getattr(client, "environment", ""),
    )

    return ToolResponse(result=result, warnings=warnings, metadata=metadata)
