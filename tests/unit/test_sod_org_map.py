"""Unit tests for get_org_security_map tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.sod.org_map import get_org_security_map


def _make_client(*, with_org_data: bool = False) -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    users = [
        {"UserID": "jsmith", "UserName": "John Smith", "PersonName": "John Smith", "Enabled": True},
        {
            "UserID": "aclerk",
            "UserName": "Alice Clerk",
            "PersonName": "Alice Clerk",
            "Enabled": True,
        },
    ]
    assignments = [
        {
            "UserId": "jsmith",
            "SecurityRoleIdentifier": "APClerk",
            "AssignmentStatus": "Enabled",
            "SecurityRoleName": "AP Clerk",
        },
        {
            "UserId": "aclerk",
            "SecurityRoleIdentifier": "Viewer",
            "AssignmentStatus": "Enabled",
            "SecurityRoleName": "Viewer",
        },
    ]
    org_data = []
    if with_org_data:
        org_data = [
            {
                "UserId": "jsmith",
                "SecurityRoleIdentifier": "APClerk",
                "SecurityRoleName": "AP Clerk",
                "InternalOrganizationName": "USMF",
                "dataAreaId": "usmf",
            },
        ]

    async def _query(entity: str, **kwargs):
        if entity == "SystemUsers":
            filter_expr = kwargs.get("filter_expr", "")
            if "UserID eq" in filter_expr:
                uid = filter_expr.split("'")[1]
                return [u for u in users if u["UserID"] == uid]
            return users
        if entity == "SecurityUserRoles":
            return assignments
        if entity == "SecurityUserRoleOrganizations":
            return org_data
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


@pytest.mark.asyncio
async def test_org_map_global_only_users():
    client = _make_client(with_org_data=False)
    response = await get_org_security_map(client)

    result = response.result
    assert result is not None
    assert result["total_users"] == 2
    assert result["users_with_org_scope"] == 0
    for user in result["users"]:
        assert user["scope"] == "global_only"
        assert user["organisation_roles"] is None


@pytest.mark.asyncio
async def test_org_map_with_org_scoped_user():
    client = _make_client(with_org_data=True)
    response = await get_org_security_map(client)

    result = response.result
    assert result["users_with_org_scope"] == 1
    jsmith = next(u for u in result["users"] if u["user_id"] == "jsmith")
    assert jsmith["scope"] == "organisation"
    assert "USMF" in jsmith["organisation_roles"]


@pytest.mark.asyncio
async def test_org_map_single_user_filter():
    client = _make_client(with_org_data=False)
    response = await get_org_security_map(client, user_id="jsmith")

    assert response.result is not None
    assert response.result["total_users"] == 1
    assert response.result["users"][0]["user_id"] == "jsmith"


@pytest.mark.asyncio
async def test_org_map_nonexistent_user():
    client = _make_client()
    response = await get_org_security_map(client, user_id="nobody")

    assert response.result is None
    assert any("not found" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_org_map_redact_pii_hashes_user_names():
    client = _make_client(with_org_data=True)
    response = await get_org_security_map(client, redact_pii=True)

    for user in response.result["users"]:
        # Redacted names should be 12-char hex hashes
        assert len(user["user_name"]) == 12
        assert all(c in "0123456789abcdef" for c in user["user_name"])
