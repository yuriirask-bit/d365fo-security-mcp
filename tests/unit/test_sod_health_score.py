"""Unit tests for get_security_health_score tool."""

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
from d365fo_security_mcp.tools.sod.health_score import get_security_health_score

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
async def test_health_score_returns_valid_structure():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_security_health_score(client, _test_ruleset())

    result = response.result
    assert result is not None
    assert 0 <= result["overall_score"] <= 100
    assert result["rating"] in ("Excellent", "Good", "Needs Attention", "Critical")
    assert "sod_compliance" in result["dimensions"]
    assert "dormant_accounts" in result["dimensions"]
    assert "role_hygiene" in result["dimensions"]
    assert "data_completeness" in result["dimensions"]
    assert isinstance(result["recommendations"], list)


@pytest.mark.asyncio
async def test_health_score_dimensions_sum_to_overall():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_security_health_score(client, _test_ruleset())

    dims = response.result["dimensions"]
    dim_sum = sum(d["score"] for d in dims.values())
    assert dim_sum == response.result["overall_score"]


@pytest.mark.asyncio
async def test_health_score_with_violations_lowers_sod_score():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_security_health_score(client, _test_ruleset())

    sod_dim = response.result["dimensions"]["sod_compliance"]
    # jsmith has a Critical violation → sod score should be < 25
    assert sod_dim["score"] < 25
    assert any("violation" in r.lower() for r in response.result["recommendations"])


@pytest.mark.asyncio
async def test_health_score_clean_environment():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    # Empty ruleset = no violations detectable
    empty_ruleset = SodRuleset(
        metadata=SodRulesetMetadata(name="Empty", version="1.0"),
        rules=[],
    )

    response = await get_security_health_score(client, empty_ruleset)

    # Should score high since no violations
    assert response.result["overall_score"] >= 50


@pytest.mark.asyncio
async def test_health_score_no_ruleset():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_security_health_score(client, None)

    # Should still produce a score (SoD dimension unavailable)
    assert response.result is not None
    assert response.result["overall_score"] >= 0


@pytest.mark.asyncio
async def test_health_score_dimension_structure():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_security_health_score(client, _test_ruleset())

    for dim in response.result["dimensions"].values():
        assert "name" in dim
        assert "score" in dim
        assert "max_score" in dim
        assert dim["max_score"] == 25
        assert "status" in dim
        assert "detail" in dim
