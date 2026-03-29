"""Unit tests for get_high_risk_users tool."""

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
from d365fo_security_mcp.tools.sod.high_risk import get_high_risk_users

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixtures() -> dict:
    return json.loads((_FIXTURES / "sod_test_users.json").read_text())


def _make_client(fixtures: dict) -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    async def _query(entity: str, **kwargs):
        if entity == "SystemUsers":
            filter_expr = kwargs.get("filter_expr", "")
            if "UserID eq" in filter_expr:
                uid = filter_expr.split("'")[1]
                return [u for u in fixtures["system_users"] if u["UserID"] == uid]
            return fixtures["system_users"]
        if entity == "SecurityUserRoles":
            return fixtures["user_role_assignments"]
        if entity == "SecurityRoleDuties":
            return fixtures["role_duties"]
        if entity == "SecuritySubRoles":
            return fixtures.get("sub_roles", [])
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
async def test_high_risk_returns_ranked_users():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_high_risk_users(client, _test_ruleset())

    assert response.result is not None
    assert response.result["high_risk_count"] >= 1
    # jsmith should be the highest risk user
    assert response.result["users"][0]["user_id"] == "jsmith"


@pytest.mark.asyncio
async def test_high_risk_top_parameter():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_high_risk_users(client, _test_ruleset(), top=1)

    assert len(response.result["users"]) <= 1


@pytest.mark.asyncio
async def test_high_risk_no_violations():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    # Empty ruleset = no violations possible
    empty_ruleset = SodRuleset(
        metadata=SodRulesetMetadata(name="Empty", version="1.0"),
        rules=[],
    )

    response = await get_high_risk_users(client, empty_ruleset)

    assert response.result["high_risk_count"] == 0
    assert "message" in response.result


@pytest.mark.asyncio
async def test_high_risk_no_ruleset():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_high_risk_users(client, None)

    assert response.result is None
    assert any("No SoD ruleset" in w for w in response.warnings)
