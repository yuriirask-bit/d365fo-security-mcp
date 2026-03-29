from __future__ import annotations

import logging
import time
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import (
    ENTITY_SECURITY_DUTIES,
    ENTITY_SECURITY_PRIVILEGES,
    ENTITY_SECURITY_ROLES,
)

logger = logging.getLogger(__name__)


async def get_role_licence_details(
    client,
    tier_config: LicenceTierConfig,
    role_identifier: str,
    summary_only: bool = False,
) -> ToolResponse:
    """Return licence tier and duty/privilege breakdown for a single security role.

    Parameters
    ----------
    client:
        An OData client with an async ``query`` method.
    tier_config:
        Licence tier configuration used to resolve display names and costs.
    role_identifier:
        The D365 F&O ``SecurityRoleIdentifier`` (e.g. ``"LEDGERACCOUNTANT"``).
    summary_only:
        If ``True``, return duties only without the full privileges array.
        Reduces response size for roles with thousands of privileges.
        ``privilege_count`` is still included as a scalar.

    Returns
    -------
    ToolResponse
        ``result`` is ``None`` when the role cannot be found; otherwise a dict
        containing role metadata, the resolved licence tier, and flat lists of
        duties and privileges for the role.
    """
    start = time.monotonic()
    warnings: list[str] = []

    # ------------------------------------------------------------------
    # 1. Look up the role.
    # ------------------------------------------------------------------
    roles_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_ROLES,
        filter_expr=f"SecurityRoleIdentifier eq '{escape_odata_string(role_identifier)}'",
        select=[
            "SecurityRoleIdentifier",
            "SecurityRoleName",
            "UserLicenseType",
            "Description",
        ],
    )

    if not roles_data:
        duration_ms = round((time.monotonic() - start) * 1000)
        return ToolResponse(
            result={
                "role_identifier": role_identifier,
                "role_name": None,
                "licence_tier": None,
                "duty_count": 0,
                "privilege_count": 0,
                "duties": [],
                "privileges": [],
            },
            metadata=ResponseMetadata(
                duration_ms=duration_ms,
                environment=getattr(client, "environment", ""),
            ),
            warnings=[f"Role not found: {role_identifier}"],
        )

    role_record = roles_data[0]
    role_name: str = role_record.get("SecurityRoleName", role_identifier)
    licence_type_name: str | None = role_record.get("UserLicenseType")

    # ------------------------------------------------------------------
    # 2. Resolve the licence tier.
    # ------------------------------------------------------------------
    if licence_type_name:
        tier = tier_config.get_by_name(licence_type_name)
    else:
        tier = tier_config.NONE_TIER
        warnings.append(
            f"Role '{role_identifier}' has no UserLicenseType; defaulting to None tier."
        )

    tier_dict: dict[str, Any] = {
        "name": tier.name,
        "display_name": tier.display_name,
        "monthly_cost": float(tier.monthly_cost),
        "annual_cost": float(tier.annual_cost),
    }

    # ------------------------------------------------------------------
    # 3. Fetch duties for the role (SecurityRoleDuties entity).
    # ------------------------------------------------------------------
    duties_data: list[dict[str, Any]] = await client.query(
        ENTITY_SECURITY_DUTIES,
        filter_expr=f"SecurityRoleIdentifier eq '{escape_odata_string(role_identifier)}'",
        select=[
            "SecurityRoleIdentifier",
            "SecurityDutyIdentifier",
            "SecurityDutyName",
        ],
    )

    # Deduplicate duties by identifier
    seen_duties: set[str] = set()
    duties_list: list[dict[str, str]] = []
    for row in duties_data:
        duty_id = row.get("SecurityDutyIdentifier", "")
        if duty_id and duty_id not in seen_duties:
            seen_duties.add(duty_id)
            duties_list.append(
                {
                    "duty_identifier": duty_id,
                    "duty_name": row.get("SecurityDutyName", duty_id),
                }
            )

    # ------------------------------------------------------------------
    # 4. Fetch privileges for the role (SecurityPrivileges entity).
    # ------------------------------------------------------------------
    privileges_list: list[dict[str, str]] = []
    privilege_count: int = 0

    if summary_only:
        # Lightweight query: fetch only identifiers to count unique privileges
        # without building the full privilege list.
        privileges_data: list[dict[str, Any]] = await client.query(
            ENTITY_SECURITY_PRIVILEGES,
            filter_expr=f"SecurityRoleIdentifier eq '{escape_odata_string(role_identifier)}'",
            select=["SecurityPrivilegeIdentifier"],
        )
        seen_privileges: set[str] = set()
        for row in privileges_data:
            priv_id = row.get("SecurityPrivilegeIdentifier", "")
            if priv_id:
                seen_privileges.add(priv_id)
        privilege_count = len(seen_privileges)
    else:
        privileges_data = await client.query(
            ENTITY_SECURITY_PRIVILEGES,
            filter_expr=f"SecurityRoleIdentifier eq '{escape_odata_string(role_identifier)}'",
            select=[
                "SecurityRoleIdentifier",
                "SecurityPrivilegeIdentifier",
                "SecurityPrivilegeName",
            ],
        )

        # Deduplicate privileges by identifier
        seen_privileges = set()
        for row in privileges_data:
            priv_id = row.get("SecurityPrivilegeIdentifier", "")
            if priv_id and priv_id not in seen_privileges:
                seen_privileges.add(priv_id)
                privileges_list.append(
                    {
                        "privilege_identifier": priv_id,
                        "privilege_name": row.get("SecurityPrivilegeName", priv_id),
                    }
                )
        privilege_count = len(privileges_list)

    # ------------------------------------------------------------------
    # 5. Assemble result.
    # ------------------------------------------------------------------
    result: dict[str, Any] = {
        "role_identifier": role_identifier,
        "role_name": role_name,
        "licence_tier": tier_dict,
        "duty_count": len(duties_list),
        "privilege_count": privilege_count,
        "duties": duties_list,
        "privileges": privileges_list,
    }

    duration_ms = round((time.monotonic() - start) * 1000)
    metadata = ResponseMetadata(
        duration_ms=duration_ms,
        environment=getattr(client, "environment", ""),
    )

    return ToolResponse(result=result, metadata=metadata, warnings=warnings)
