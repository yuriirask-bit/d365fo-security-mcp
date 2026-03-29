"""Unit tests for run_user_access_review tool."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodDutyGroup,
    SodRuleset,
    SodRulesetMetadata,
)
from d365fo_security_mcp.tools.sod.access_review import run_user_access_review

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
        if entity == "SecurityRoleDuties":
            return fixtures["role_duties"]
        if entity == "SecuritySubRoles":
            return fixtures.get("sub_roles", [])
        if entity == "UserSessionLogs":
            return []
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


def _test_ruleset() -> SodRuleset:
    return SodRuleset(
        metadata=SodRulesetMetadata(name="Test", version="1.0"),
        rules=[
            SodConflictRule(
                id="SOD-AP-001",
                name="Vendor vs Payment",
                category="accounts_payable",
                risk_level="Critical",
                description="Test",
                duty_group_a=SodDutyGroup(name="A", duties=["VendTableMaintain"]),
                duty_group_b=SodDutyGroup(
                    name="B",
                    duties=["VendPaymProposalApprove", "LedgerJournalizeTransactionPost"],
                ),
            )
        ],
    )


@pytest.mark.asyncio
async def test_access_review_lists_all_enabled_users():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await run_user_access_review(client, _test_ruleset())

    result = response.result
    assert result is not None
    assert result["total_users"] == 3
    user_ids = {u["user_id"] for u in result["users"]}
    assert "jsmith" in user_ids
    assert "cleanuser" in user_ids


@pytest.mark.asyncio
async def test_access_review_sod_flags():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await run_user_access_review(client, _test_ruleset())

    jsmith = next(u for u in response.result["users"] if u["user_id"] == "jsmith")
    cleanuser = next(u for u in response.result["users"] if u["user_id"] == "cleanuser")

    assert jsmith["has_sod_violations"] is True
    assert jsmith["sod_violation_count"] >= 1
    assert cleanuser["has_sod_violations"] is False


@pytest.mark.asyncio
async def test_access_review_sod_only_filter():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await run_user_access_review(client, _test_ruleset(), sod_only=True)

    # Only users with violations
    for user in response.result["users"]:
        assert user["has_sod_violations"] is True
    assert response.result["total_users"] >= 1


@pytest.mark.asyncio
async def test_access_review_no_ruleset_warns():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await run_user_access_review(client, None)

    assert response.result is not None
    assert any("No SoD ruleset" in w for w in response.warnings)
    # All users should still be listed, just without SoD flags
    for user in response.result["users"]:
        assert user["has_sod_violations"] is False
