"""Unit tests for get_sod_conflict_matrix tool."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodDutyGroup,
    SodRuleset,
    SodRulesetMetadata,
)
from d365fo_security_mcp.tools.sod.matrix import get_sod_conflict_matrix


def _ruleset() -> SodRuleset:
    rules = [
        SodConflictRule(
            id="SOD-AP-001",
            name="Vendor vs Payment",
            category="accounts_payable",
            risk_level="Critical",
            description="Vendor maintenance and payment approval conflict",
            duty_group_a=SodDutyGroup(name="A", duties=["D1"]),
            duty_group_b=SodDutyGroup(name="B", duties=["D2"]),
        ),
        SodConflictRule(
            id="SOD-GL-001",
            name="Journal vs Approval",
            category="general_ledger",
            risk_level="High",
            description="Journal entry and journal approval conflict",
            duty_group_a=SodDutyGroup(name="C", duties=["D3"]),
            duty_group_b=SodDutyGroup(name="D", duties=["D4"]),
        ),
    ]
    return SodRuleset(
        metadata=SodRulesetMetadata(
            name="Test Ruleset",
            version="1.0",
            rule_count=2,
            category_count=2,
        ),
        rules=rules,
    )


@pytest.mark.asyncio
async def test_matrix_returns_all_rules():
    response = await get_sod_conflict_matrix(_ruleset())

    assert response.result is not None
    assert response.result["rule_count"] == 2
    assert response.result["ruleset_name"] == "Test Ruleset"
    assert response.result["version"] == "1.0"
    assert len(response.result["rules"]) == 2


@pytest.mark.asyncio
async def test_matrix_returns_categories():
    response = await get_sod_conflict_matrix(_ruleset())

    assert sorted(response.result["categories"]) == [
        "accounts_payable",
        "general_ledger",
    ]


@pytest.mark.asyncio
async def test_matrix_category_filter():
    response = await get_sod_conflict_matrix(_ruleset(), category="accounts_payable")

    assert response.result["rule_count"] == 1
    assert response.result["rules"][0]["id"] == "SOD-AP-001"
    # Categories list still shows all available categories
    assert len(response.result["categories"]) == 2


@pytest.mark.asyncio
async def test_matrix_invalid_category_warns():
    response = await get_sod_conflict_matrix(_ruleset(), category="nonexistent")

    assert response.result["rule_count"] == 0
    assert len(response.result["rules"]) == 0
    assert any("Unknown category" in w for w in response.warnings)
    assert any("accounts_payable" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_matrix_no_ruleset():
    response = await get_sod_conflict_matrix(None)

    assert response.result is None
    assert any("No SoD ruleset configured" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_matrix_rule_structure():
    response = await get_sod_conflict_matrix(_ruleset())

    rule = response.result["rules"][0]
    assert "id" in rule
    assert "name" in rule
    assert "category" in rule
    assert "risk_level" in rule
    assert "description" in rule
    assert "duty_group_a" in rule
    assert "duty_group_b" in rule
    assert "duties" in rule["duty_group_a"]


@pytest.mark.asyncio
async def test_matrix_metadata():
    response = await get_sod_conflict_matrix(_ruleset())

    assert response.metadata.provider == "sod"
    assert response.metadata.duration_ms >= 0
