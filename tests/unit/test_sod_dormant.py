"""Unit tests for find_dormant_privileged_accounts tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.models.sod import SodRuleset, SodRulesetMetadata
from d365fo_security_mcp.tools.sod.dormant import find_dormant_privileged_accounts


def _make_client() -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    users = [
        {
            "UserID": "admin",
            "UserName": "Admin",
            "PersonName": "Admin",
            "Email": "",
            "Enabled": True,
        },
        {
            "UserID": "jsmith",
            "UserName": "John Smith",
            "PersonName": "John Smith",
            "Email": "",
            "Enabled": True,
        },
    ]
    assignments = [
        {
            "UserId": "admin",
            "SecurityRoleIdentifier": "-SYSADMIN-",
            "AssignmentStatus": "Enabled",
            "SecurityRoleName": "System administrator",
        },
        {
            "UserId": "jsmith",
            "SecurityRoleIdentifier": "APClerk",
            "AssignmentStatus": "Enabled",
            "SecurityRoleName": "AP Clerk",
        },
    ]

    async def _query(entity: str, **kwargs):
        if entity == "SystemUsers":
            return users
        if entity == "SecurityUserRoles":
            return assignments
        if entity == "SecurityRoleDuties":
            return []
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


def _ruleset_with_privileged() -> SodRuleset:
    return SodRuleset(
        metadata=SodRulesetMetadata(name="Test", version="1.0"),
        privileged_roles=["-SYSADMIN-"],
        rules=[],
    )


@pytest.mark.asyncio
async def test_dormant_finds_privileged_users_with_no_login():
    client = _make_client()
    ruleset = _ruleset_with_privileged()

    response = await find_dormant_privileged_accounts(client, ruleset, days=90)

    result = response.result
    assert result is not None
    assert result["dormant_count"] >= 1
    # admin has -SYSADMIN- and no login data → dormant
    dormant_ids = {u["user_id"] for u in result["users"]}
    assert "admin" in dormant_ids
    # jsmith has APClerk which is not privileged → not listed
    assert "jsmith" not in dormant_ids


@pytest.mark.asyncio
async def test_dormant_no_privileged_users():
    client = _make_client()
    # Ruleset with privileged_roles that match nobody
    ruleset = SodRuleset(
        metadata=SodRulesetMetadata(name="Test", version="1.0"),
        privileged_roles=["NonExistentRole"],
        rules=[],
    )

    response = await find_dormant_privileged_accounts(client, ruleset, days=90)

    assert response.result["dormant_count"] == 0
    assert response.result["message"] == "No users with privileged roles found."


@pytest.mark.asyncio
async def test_dormant_redact_pii():
    client = _make_client()
    ruleset = _ruleset_with_privileged()

    response = await find_dormant_privileged_accounts(client, ruleset, days=90, redact_pii=True)

    for user in response.result["users"]:
        assert user["user_name"] != "Admin"


@pytest.mark.asyncio
async def test_dormant_login_data_unavailable_warns():
    client = _make_client()
    ruleset = _ruleset_with_privileged()

    response = await find_dormant_privileged_accounts(client, ruleset, days=90)

    # Both D365 and Graph unavailable in test → warning
    assert any("unavailable" in w.lower() for w in response.warnings)
