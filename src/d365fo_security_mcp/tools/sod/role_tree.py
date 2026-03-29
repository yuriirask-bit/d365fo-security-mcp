"""get_role_duty_tree — full duty/privilege hierarchy for a role."""

from __future__ import annotations

import logging
import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SECURITY_ROLES,
    ENTITY_SECURITY_SUB_ROLES,
)
from d365fo_security_mcp.tools.sod.detector import (
    build_sub_role_map,
    resolve_sub_roles,
)

logger = logging.getLogger(__name__)


async def get_role_duty_tree(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    role: str,
    include_sod_flags: bool = False,
) -> ToolResponse:
    """Return the full duty/privilege hierarchy for a role.

    Includes sub-role resolution and optional SoD conflict annotations.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    # Verify role exists
    roles_data = await client.query(
        ENTITY_SECURITY_ROLES,
        filter_expr=f"SecurityRoleIdentifier eq '{escape_odata_string(role)}'",
        select=["SecurityRoleIdentifier", "SecurityRoleName"],
    )
    if not roles_data:
        return ToolResponse(
            result=None,
            metadata=ResponseMetadata(
                provider="sod",
                environment=client.environment,
                duration_ms=int((time.perf_counter() - start) * 1000),
                currency="",
            ),
            warnings=[f"Role '{role}' not found."],
        )

    role_name = roles_data[0].get("SecurityRoleName", role)

    # Fetch sub-roles
    try:
        sub_roles_data = await client.query(
            ENTITY_SECURITY_SUB_ROLES,
            select=[
                "SecurityRoleIdentifier",
                "SecuritySubRoleIdentifier",
                "SecuritySubRoleName",
            ],
        )
    except (RuntimeError, TimeoutError, OSError):
        sub_roles_data = []
        warnings.append("Sub-role data unavailable.")

    sub_role_map = build_sub_role_map(sub_roles_data)
    effective_role_ids = resolve_sub_roles({role}, sub_role_map)

    # Build sub-role name lookup
    sub_role_names: dict[str, str] = {}
    for row in sub_roles_data:
        sid = row.get("SecuritySubRoleIdentifier", "")
        sname = row.get("SecuritySubRoleName", "")
        if sid and sname:
            sub_role_names[sid] = sname

    # Fetch duties and privileges separately
    from d365fo_security_mcp.tools.constants import ENTITY_SECURITY_PRIVILEGES

    duties_data = await client.query(
        ENTITY_SECURITY_DUTIES,
        select=[
            "SecurityRoleIdentifier",
            "SecurityDutyIdentifier",
            "SecurityDutyName",
        ],
    )
    # Fetch privileges per role (D365 OData maps role→privilege, not duty→privilege)
    privileges_data = await client.query(
        ENTITY_SECURITY_PRIVILEGES,
        select=[
            "SecurityRoleIdentifier",
            "SecurityPrivilegeIdentifier",
            "SecurityPrivilegeName",
        ],
    )

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

    # Build SoD duty set for annotation
    sod_duties: set[str] = set()
    if include_sod_flags and ruleset and ruleset.rules:
        for r in ruleset.rules:
            sod_duties.update(r.duty_group_a.duties)
            sod_duties.update(r.duty_group_b.duties)
    elif include_sod_flags and ruleset is None:
        warnings.append("No SoD ruleset configured; cannot annotate SoD flags.")

    # Group by role → duties (privileges are at role level, not duty level)
    role_trees: dict[str, dict[str, dict[str, Any]]] = {}
    for row in duties_data:
        rid = row.get("SecurityRoleIdentifier", "")
        if rid not in effective_role_ids:
            continue
        did = row.get("SecurityDutyIdentifier", "")
        dname = row.get("SecurityDutyName", "")

        if rid not in role_trees:
            role_trees[rid] = {}
        if did not in role_trees[rid]:
            entry: dict[str, Any] = {
                "duty_id": did,
                "duty_name": dname,
            }
            if include_sod_flags:
                entry["sod_conflict"] = did in sod_duties
            role_trees[rid][did] = entry

    # Assemble result
    sub_roles_list: list[dict[str, Any]] = []
    for rid in sorted(effective_role_ids - {role}):
        sub_roles_list.append(
            {
                "role_id": rid,
                "role_name": sub_role_names.get(rid, rid),
                "duty_count": len(role_trees.get(rid, {})),
                "duties": list(role_trees.get(rid, {}).values()),
                "privileges": privs_by_role.get(rid, []),
            }
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    result: dict[str, Any] = {
        "role_id": role,
        "role_name": role_name,
        "duty_count": len(role_trees.get(role, {})),
        "duties": list(role_trees.get(role, {}).values()),
        "privileges": privs_by_role.get(role, []),
        "sub_roles": sub_roles_list,
    }

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
