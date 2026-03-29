"""Unit tests for get_all_user_role_assignments tool."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.sod.assignments import get_all_user_role_assignments

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixtures() -> dict:
    return json.loads((_FIXTURES / "sod_test_users.json").read_text())


def _make_client(fixtures: dict) -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    async def _query(entity: str, **kwargs):
        if entity == "SystemUsers":
            return fixtures["system_users"]
        if entity == "SecurityUserRoles":
            return fixtures["user_role_assignments"]
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


@pytest.mark.asyncio
async def test_assignments_returns_all_users():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_all_user_role_assignments(client)

    result = response.result
    assert result is not None
    assert result["total_users"] == 3
    user_ids = {u["user_id"] for u in result["users"]}
    assert "jsmith" in user_ids
    assert "aclerk" in user_ids
    assert "cleanuser" in user_ids


@pytest.mark.asyncio
async def test_assignments_include_role_details():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_all_user_role_assignments(client)

    jsmith = next(u for u in response.result["users"] if u["user_id"] == "jsmith")
    assert jsmith["role_count"] == 2
    role_ids = {r["role_id"] for r in jsmith["roles"]}
    assert "APClerk" in role_ids
    assert "PaymentMgr" in role_ids


@pytest.mark.asyncio
async def test_assignments_active_only_filter():
    fixtures = _load_fixtures()
    # Add an expired assignment
    fixtures["user_role_assignments"].append(
        {
            "UserId": "jsmith",
            "SecurityRoleIdentifier": "OldRole",
            "AssignmentStatus": "Expired",
            "SecurityRoleName": "Old Role",
        }
    )
    client = _make_client(fixtures)

    response = await get_all_user_role_assignments(client, active_only=True)

    jsmith = next(u for u in response.result["users"] if u["user_id"] == "jsmith")
    role_ids = {r["role_id"] for r in jsmith["roles"]}
    assert "OldRole" not in role_ids


@pytest.mark.asyncio
async def test_assignments_redact_pii_hashes_user_names():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_all_user_role_assignments(client, redact_pii=True)

    for user in response.result["users"]:
        # Redacted names should be 12-char hex hashes, not original names
        assert user["user_name"] != ""
        assert len(user["user_name"]) == 12
        assert all(c in "0123456789abcdef" for c in user["user_name"])


@pytest.mark.asyncio
async def test_assignments_metadata():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_all_user_role_assignments(client)

    assert response.metadata.provider == "sod"
    assert response.metadata.duration_ms >= 0
