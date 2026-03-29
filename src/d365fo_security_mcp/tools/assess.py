from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTier, LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SECURITY_ROLES,
    ENTITY_SYSTEM_USERS,
    ENTITY_USER_ROLE_ASSOCIATIONS,
)

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if should_redact:
        return hashlib.sha256(value.encode()).hexdigest()[:12]
    return value


def _build_duty_counts(duties_data: list[dict[str, Any]]) -> dict[str, int]:
    """Build a mapping of SecurityRoleIdentifier to distinct duty count."""
    duty_sets: dict[str, set[str]] = {}
    for duty in duties_data:
        role_id = duty.get("SecurityRoleIdentifier", "")
        duty_id = duty.get("SecurityDutyIdentifier", "")
        if role_id and duty_id:
            duty_sets.setdefault(role_id, set()).add(duty_id)
    return {role_id: len(duties) for role_id, duties in duty_sets.items()}


def _select_driving_role(
    candidates: list[tuple[str, str]],
    duty_counts: dict[str, int],
) -> str | None:
    """Select the driving role from candidates at the highest tier.

    Each candidate is a (role_identifier, role_name) tuple.
    Picks the role with the highest duty count; ties broken alphabetically by role name.
    Returns the role_identifier of the winner, or None if candidates is empty.
    """
    if not candidates:
        return None
    best = max(
        candidates,
        key=lambda c: (duty_counts.get(c[0], 0), _sort_key_alpha_asc(c[1])),
    )
    return best[0]


def _sort_key_alpha_asc(name: str) -> str:
    """Return a sort key that makes alphabetically earlier names sort higher.

    We negate alphabetical order so that ``max()`` picks the alphabetically
    first name when duty counts are tied.
    """
    # Invert each character so 'A' > 'Z' when compared lexicographically.
    # This lets us use max() with a single pass.
    return "".join(chr(0x10FFFF - ord(c)) for c in name.lower())


async def assess_user(
    client: ODataClient,
    tier_config: LicenceTierConfig,
    user_id: str,
    *,
    redact_pii: bool = False,
) -> ToolResponse:
    start = time.monotonic()
    warnings: list[str] = []

    # Query all security roles
    roles_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_ROLES,
        select=["SecurityRoleIdentifier", "SecurityRoleName", "UserLicenseType"],
    )

    # Build role_id -> (role_name, licence_type_name)
    role_lookup: dict[str, tuple[str, str | None]] = {}
    for role in roles_data:
        role_id = role.get("SecurityRoleIdentifier", "")
        role_name = role.get("SecurityRoleName", "")
        licence_type = role.get("UserLicenseType")
        role_lookup[role_id] = (role_name, licence_type)

    # Query user role assignments filtered by UserId
    assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
        filter_expr=f"UserId eq '{escape_odata_string(user_id)}'",
    )

    # Filter active assignments and collect tier names
    tier_names: list[str] = []
    active_assignments: list[dict[str, Any]] = []
    for assignment in assignments:
        status = assignment.get("AssignmentStatus", "")
        if status in ("Expired", "Suspended"):
            continue
        active_assignments.append(assignment)
        role_id = assignment.get("SecurityRoleIdentifier", "")
        role_name_val, licence_type_name = role_lookup.get(role_id, ("", None))
        if licence_type_name:
            tier_names.append(licence_type_name)
        else:
            warnings.append(
                f"Role '{role_id}' has no UserLicenseType; assuming highest tier (conservative)."
            )
            # Conservative: use the highest possible tier name by adding a sentinel
            highest_tier = tier_config.highest_tier([t.name for t in tier_config.tiers])
            if highest_tier:
                tier_names.append(highest_tier.name)

    # Determine required tier
    required_tier: LicenceTier | None = tier_config.highest_tier(tier_names)

    # Collect roles and find candidates at the highest tier for driving_role selection
    roles_list: list[dict[str, Any]] = []
    driving_candidates: list[tuple[str, str]] = []  # (role_id, role_name)
    for assignment in active_assignments:
        role_id = assignment.get("SecurityRoleIdentifier", "")
        role_name_val, licence_type_name = role_lookup.get(role_id, ("", None))
        tier_obj: LicenceTier | None = None
        if licence_type_name:
            tier_obj = tier_config.get_by_name(licence_type_name)
        else:
            tier_obj = tier_config.highest_tier([t.name for t in tier_config.tiers])

        if (
            required_tier is not None
            and tier_obj is not None
            and tier_obj.name == required_tier.name
        ):
            driving_candidates.append((role_id, role_name_val))

        roles_list.append(
            {
                "role_identifier": role_id,
                "role_name": role_name_val,
                "licence_tier": (
                    {
                        "name": tier_obj.name,
                        "display_name": tier_obj.display_name,
                        "monthly_cost": float(tier_obj.monthly_cost),
                    }
                    if tier_obj is not None
                    else None
                ),
                "is_driving": False,  # will be set below
            }
        )

    # Query duties only when tiebreaker is needed (2+ candidates at highest tier)
    duty_counts: dict[str, int] = {}
    if len(driving_candidates) > 1:
        duties_data: list[dict[str, Any]] = await client.query(
            ENTITY_SECURITY_DUTIES,
            select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
        )
        duty_counts = _build_duty_counts(duties_data)

    driving_role = _select_driving_role(driving_candidates, duty_counts)

    # Mark the driving role in the roles list
    for role_entry in roles_list:
        if role_entry["role_identifier"] == driving_role:
            role_entry["is_driving"] = True
            break

    result: dict[str, Any] = {
        "user_id": _redact(user_id, redact_pii),
        "required_tier": (
            {
                "name": required_tier.name,
                "display_name": required_tier.display_name,
                "monthly_cost": float(required_tier.monthly_cost),
            }
            if required_tier is not None
            else None
        ),
        "driving_role": driving_role,
        "role_count": len(roles_list),
        "roles": roles_list,
    }

    duration_ms = int((time.monotonic() - start) * 1000)
    metadata = ResponseMetadata(
        duration_ms=duration_ms,
        environment=client.environment,
    )

    return ToolResponse(result=result, metadata=metadata, warnings=warnings)


async def assess_all_users(
    client: ODataClient,
    tier_config: LicenceTierConfig,
    *,
    redact_pii: bool = False,
    batch_size: int = 50,
    tier_filter: str = "",
    min_role_count: int = 0,
    include_roles: bool = True,
) -> ToolResponse:
    start = time.monotonic()
    warnings: list[str] = []

    # Query all security roles
    roles_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_ROLES,
        select=["SecurityRoleIdentifier", "SecurityRoleName", "UserLicenseType"],
    )

    # Build role_id -> (role_name, licence_type_name)
    role_lookup: dict[str, tuple[str, str | None]] = {}
    for role in roles_data:
        role_id = role.get("SecurityRoleIdentifier", "")
        role_name = role.get("SecurityRoleName", "")
        licence_type = role.get("UserLicenseType")
        role_lookup[role_id] = (role_name, licence_type)

    # Query duties once for driving_role tiebreaker
    duties_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_DUTIES,
        select=["SecurityRoleIdentifier", "SecurityDutyIdentifier"],
    )
    duty_counts: dict[str, int] = _build_duty_counts(duties_data)

    # Query all enabled system users
    users_data: list[dict[str, Any]] = await client.query(
        ENTITY_SYSTEM_USERS,
        filter_expr="Enabled eq true",
        select=["UserID", "UserName", "PersonName", "Email", "Enabled"],
    )

    # Query ALL user role assignments at once for efficiency
    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )

    # Group assignments by UserId
    assignments_by_user: dict[str, list[dict[str, Any]]] = {}
    for assignment in all_assignments:
        uid = assignment.get("UserId", "")
        assignments_by_user.setdefault(uid, []).append(assignment)

    assessments: list[dict[str, Any]] = []

    # Process users (batch_size controls memory-conscious iteration)
    for batch_start in range(0, len(users_data), batch_size):
        batch = users_data[batch_start : batch_start + batch_size]
        for user in batch:
            user_id = user.get("UserID", "")
            user_name = user.get("PersonName") or user.get("UserName", "")
            user_email = user.get("Email", "")

            user_assignments = assignments_by_user.get(user_id, [])

            # Filter active assignments and collect tier names
            tier_names: list[str] = []
            active_assignments: list[dict[str, Any]] = []
            for assignment in user_assignments:
                status = assignment.get("AssignmentStatus", "")
                if status in ("Expired", "Suspended"):
                    continue
                active_assignments.append(assignment)
                role_id = assignment.get("SecurityRoleIdentifier", "")
                _, licence_type_name = role_lookup.get(role_id, ("", None))
                if licence_type_name:
                    tier_names.append(licence_type_name)
                else:
                    safe_uid = _redact(user_id, redact_pii)
                    warnings.append(
                        f"Role '{role_id}' assigned to user '{safe_uid}' has no UserLicenseType; "
                        "assuming highest tier (conservative)."
                    )
                    highest_tier = tier_config.highest_tier([t.name for t in tier_config.tiers])
                    if highest_tier:
                        tier_names.append(highest_tier.name)

            required_tier: LicenceTier | None = tier_config.highest_tier(tier_names)

            roles_list: list[dict[str, Any]] = []
            driving_candidates: list[tuple[str, str]] = []  # (role_id, role_name)
            for assignment in active_assignments:
                role_id = assignment.get("SecurityRoleIdentifier", "")
                role_name_val, licence_type_name = role_lookup.get(role_id, ("", None))
                tier_obj: LicenceTier | None = None
                if licence_type_name:
                    tier_obj = tier_config.get_by_name(licence_type_name)
                else:
                    tier_obj = tier_config.highest_tier([t.name for t in tier_config.tiers])

                if (
                    required_tier is not None
                    and tier_obj is not None
                    and tier_obj.name == required_tier.name
                ):
                    driving_candidates.append((role_id, role_name_val))

                roles_list.append(
                    {
                        "role_identifier": role_id,
                        "role_name": role_name_val,
                        "licence_tier": (
                            {
                                "name": tier_obj.name,
                                "display_name": tier_obj.display_name,
                                "monthly_cost": float(tier_obj.monthly_cost),
                            }
                            if tier_obj is not None
                            else None
                        ),
                        "is_driving": False,  # will be set below
                    }
                )

            driving_role = _select_driving_role(driving_candidates, duty_counts)

            # Mark the driving role in the roles list
            for role_entry in roles_list:
                if role_entry["role_identifier"] == driving_role:
                    role_entry["is_driving"] = True
                    break

            assessments.append(
                {
                    "user_id": _redact(user_id, redact_pii),
                    "user_name": _redact(user_name, redact_pii),
                    "user_email": _redact(user_email, redact_pii),
                    "required_tier": (
                        {
                            "name": required_tier.name,
                            "display_name": required_tier.display_name,
                            "monthly_cost": float(required_tier.monthly_cost),
                        }
                        if required_tier is not None
                        else None
                    ),
                    "driving_role": driving_role,
                    "role_count": len(roles_list),
                    "roles": roles_list,
                }
            )

    # Post-filtering
    if tier_filter:
        if tier_filter not in tier_config.valid_tier_names:
            warnings.append(
                f"Invalid tier_filter '{tier_filter}'. "
                f"Valid tier names: {', '.join(tier_config.valid_tier_names)}"
            )
            assessments = []
        else:
            assessments = [
                a
                for a in assessments
                if a["required_tier"] is not None and a["required_tier"]["name"] == tier_filter
            ]

    if min_role_count > 0:
        assessments = [a for a in assessments if a["role_count"] >= min_role_count]

    if not include_roles:
        for a in assessments:
            a.pop("roles", None)

    result: dict[str, Any] = {
        "total_users": len(assessments),
        "assessments": assessments,
    }

    duration_ms = int((time.monotonic() - start) * 1000)
    metadata = ResponseMetadata(
        duration_ms=duration_ms,
        environment=client.environment,
    )

    return ToolResponse(result=result, metadata=metadata, warnings=warnings)
