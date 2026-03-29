"""get_user_security_profile — full role→duty→privilege hierarchy for a user."""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
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
    resolve_sub_roles,
)

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def get_user_security_profile(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    user_id: str,
    redact_pii: bool = False,
    summary_only: bool = False,
) -> ToolResponse:
    """Return a user's complete security profile with SoD violations.

    Builds a hierarchical view: user → roles → duties → privileges,
    plus any SoD violations detected for the user.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    # Fetch user
    users_data = await client.query(
        ENTITY_SYSTEM_USERS,
        filter_expr=f"UserID eq '{escape_odata_string(user_id)}'",
        select=["UserID", "UserName", "PersonName", "Email", "Enabled"],
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

    user = users_data[0]
    uid = user.get("UserID", "")
    uname = user.get("PersonName") or user.get("UserName", uid)
    uemail = user.get("Email", "")

    # Fetch role assignments for this user
    all_assignments: list[dict[str, Any]] = await client.query(
        ENTITY_USER_ROLE_ASSOCIATIONS,
    )
    user_assignments = [
        a
        for a in all_assignments
        if a.get("UserId") == uid and a.get("AssignmentStatus") not in ("Expired", "Suspended")
    ]
    assigned_role_ids = {a.get("SecurityRoleIdentifier", "") for a in user_assignments}

    # Fetch duties (role→duty mapping) and privileges separately
    duties_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_DUTIES,
        select=[
            "SecurityRoleIdentifier",
            "SecurityDutyIdentifier",
            "SecurityDutyName",
        ],
    )

    from d365fo_security_mcp.tools.constants import ENTITY_SECURITY_PRIVILEGES

    # Fetch privileges per role (D365 OData maps role→privilege, not duty→privilege)
    # Skip this expensive query when summary_only mode is active.
    if summary_only:
        privileges_data: list[dict[str, Any]] = []
    else:
        privileges_data = await client.query(
            ENTITY_SECURITY_PRIVILEGES,
            select=[
                "SecurityRoleIdentifier",
                "SecurityPrivilegeIdentifier",
                "SecurityPrivilegeName",
            ],
        )

    # Fetch sub-roles
    try:
        sub_roles_data: list[dict[str, Any]] = await client.query(
            ENTITY_SECURITY_SUB_ROLES,
            select=["SecurityRoleIdentifier", "SecuritySubRoleIdentifier"],
        )
    except (RuntimeError, TimeoutError, OSError):
        sub_roles_data = []
        warnings.append("Sub-role data unavailable.")

    sub_role_map = build_sub_role_map(sub_roles_data)
    effective_role_ids = resolve_sub_roles(assigned_role_ids, sub_role_map)

    # Build privilege lookup: role_id → list of privileges
    privs_by_role: dict[str, list[dict[str, str]]] = {}
    for row in privileges_data:
        rid = row.get("SecurityRoleIdentifier", "")
        if rid not in effective_role_ids:
            continue
        pid = row.get("SecurityPrivilegeIdentifier", "")
        pname = row.get("SecurityPrivilegeName", "")
        if pid:
            privs_by_role.setdefault(rid, []).append({"privilege_id": pid, "privilege_name": pname})

    # Build hierarchical structure: role → duties + privileges
    role_duties: dict[str, dict[str, dict[str, Any]]] = {}
    for row in duties_data:
        role_id = row.get("SecurityRoleIdentifier", "")
        if role_id not in effective_role_ids:
            continue
        duty_id = row.get("SecurityDutyIdentifier", "")
        duty_name = row.get("SecurityDutyName", "")

        if role_id not in role_duties:
            role_duties[role_id] = {}
        if duty_id not in role_duties[role_id]:
            role_duties[role_id][duty_id] = {
                "duty_id": duty_id,
                "duty_name": duty_name,
            }

    # Build role name lookup from assignments
    role_names: dict[str, str] = {}
    for a in user_assignments:
        rid = a.get("SecurityRoleIdentifier", "")
        rname = a.get("SecurityRoleName", "")
        if rid and rname:
            role_names[rid] = rname

    # Assemble roles list
    roles_list: list[dict[str, Any]] = []
    for role_id in sorted(effective_role_ids):
        duties_dict = role_duties.get(role_id, {})
        if summary_only:
            roles_list.append(
                {
                    "role_id": role_id,
                    "role_name": role_names.get(role_id, role_id),
                    "is_sub_role": role_id not in assigned_role_ids,
                    "duty_count": len(duties_dict),
                    "privilege_count": 0,
                    "duties": [],
                    "privileges": [],
                }
            )
        else:
            roles_list.append(
                {
                    "role_id": role_id,
                    "role_name": role_names.get(role_id, role_id),
                    "is_sub_role": role_id not in assigned_role_ids,
                    "duties": list(duties_dict.values()),
                    "privileges": privs_by_role.get(role_id, []),
                }
            )

    # SoD violations
    sod_violations: list[dict[str, Any]] = []
    if ruleset and ruleset.rules:
        role_duty_map = build_role_duty_map(
            [
                {"SecurityRoleIdentifier": r, "SecurityDutyIdentifier": d}
                for r, duties in role_duties.items()
                for d in duties
            ]
        )
        sod_result = detect_for_user(
            user_id=uid,
            user_name=uname,
            assigned_role_ids=assigned_role_ids,
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=ruleset,
        )
        sod_violations = [v.model_dump() for v in sod_result.violations]
    elif ruleset is None:
        warnings.append("No SoD ruleset configured; violations not checked.")

    duration_ms = int((time.perf_counter() - start) * 1000)

    result: dict[str, Any] = {
        "user_id": uid,
        "user_name": _redact(uname, redact_pii),
        "email": _redact(uemail, redact_pii),
        "enabled": user.get("Enabled", True),
        "role_count": len(roles_list),
        "roles": roles_list,
        "sod_violations": sod_violations,
    }
    if summary_only:
        result["summary_mode"] = True

    return ToolResponse(
        result=result,
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=warnings,
    )
