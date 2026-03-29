"""Unit tests for get_role_duty_tree tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodDutyGroup,
    SodRuleset,
    SodRulesetMetadata,
)
from d365fo_security_mcp.tools.sod.role_tree import get_role_duty_tree


def _make_client() -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    roles = [
        {"SecurityRoleIdentifier": "APClerk", "SecurityRoleName": "AP Clerk"},
    ]
    duties = [
        {
            "SecurityRoleIdentifier": "APClerk",
            "SecurityDutyIdentifier": "VendTableMaintain",
            "SecurityDutyName": "Maintain vendor master",
        },
        {
            "SecurityRoleIdentifier": "APClerk",
            "SecurityDutyIdentifier": "PurchOrderMaintain",
            "SecurityDutyName": "Maintain purchase orders",
        },
        {
            "SecurityRoleIdentifier": "SubRole1",
            "SecurityDutyIdentifier": "SubDuty1",
            "SecurityDutyName": "Sub duty",
        },
    ]
    privileges = [
        {
            "SecurityRoleIdentifier": "APClerk",
            "SecurityPrivilegeIdentifier": "VendTable_W",
            "SecurityPrivilegeName": "Write vendor table",
        },
        {
            "SecurityRoleIdentifier": "APClerk",
            "SecurityPrivilegeIdentifier": "PurchOrder_W",
            "SecurityPrivilegeName": "Write purchase orders",
        },
    ]
    sub_roles = [
        {
            "SecurityRoleIdentifier": "APClerk",
            "SecuritySubRoleIdentifier": "SubRole1",
            "SecuritySubRoleName": "Sub Role One",
        },
    ]

    async def _query(entity: str, **kwargs):
        if entity == "SecurityRoles":
            filter_expr = kwargs.get("filter_expr", "")
            if "APClerk" in filter_expr:
                return roles
            return []
        if entity == "SecurityRoleDuties":
            return duties
        if entity == "SecurityPrivileges":
            return privileges
        if entity == "SecuritySubRoles":
            return sub_roles
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


def _test_ruleset() -> SodRuleset:
    return SodRuleset(
        metadata=SodRulesetMetadata(name="Test", version="1.0"),
        rules=[
            SodConflictRule(
                id="SOD-001",
                name="Test",
                category="test",
                risk_level="High",
                description="Test",
                duty_group_a=SodDutyGroup(name="A", duties=["VendTableMaintain"]),
                duty_group_b=SodDutyGroup(name="B", duties=["SomethingElse"]),
            )
        ],
    )


@pytest.mark.asyncio
async def test_role_tree_returns_hierarchy():
    client = _make_client()
    response = await get_role_duty_tree(client, None, role="APClerk")

    result = response.result
    assert result is not None
    assert result["role_id"] == "APClerk"
    assert result["role_name"] == "AP Clerk"
    assert result["duty_count"] == 2
    assert len(result["duties"]) == 2


@pytest.mark.asyncio
async def test_role_tree_includes_sub_roles():
    client = _make_client()
    response = await get_role_duty_tree(client, None, role="APClerk")

    assert len(response.result["sub_roles"]) == 1
    assert response.result["sub_roles"][0]["role_id"] == "SubRole1"
    assert response.result["sub_roles"][0]["role_name"] == "Sub Role One"


@pytest.mark.asyncio
async def test_role_tree_sod_flags():
    client = _make_client()
    response = await get_role_duty_tree(
        client, _test_ruleset(), role="APClerk", include_sod_flags=True
    )

    duties = response.result["duties"]
    vendor_duty = next(d for d in duties if d["duty_id"] == "VendTableMaintain")
    purch_duty = next(d for d in duties if d["duty_id"] == "PurchOrderMaintain")

    assert vendor_duty["sod_conflict"] is True
    assert purch_duty["sod_conflict"] is False


@pytest.mark.asyncio
async def test_role_tree_invalid_role():
    client = _make_client()
    response = await get_role_duty_tree(client, None, role="NonExistent")

    assert response.result is None
    assert any("not found" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_role_tree_privileges_at_role_level():
    """D365 OData maps privileges to roles, not duties."""
    client = _make_client()
    response = await get_role_duty_tree(client, None, role="APClerk")

    # Privileges are at role level, not nested under duties
    assert len(response.result["privileges"]) == 2
    priv_ids = {p["privilege_id"] for p in response.result["privileges"]}
    assert "VendTable_W" in priv_ids
    assert "PurchOrder_W" in priv_ids
