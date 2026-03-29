"""Unit tests for get_user_security_profile tool."""

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
from d365fo_security_mcp.tools.sod.profile import get_user_security_profile

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
                description="Test conflict",
                duty_group_a=SodDutyGroup(name="A", duties=["VendTableMaintain"]),
                duty_group_b=SodDutyGroup(
                    name="B",
                    duties=["VendPaymProposalApprove", "LedgerJournalizeTransactionPost"],
                ),
            )
        ],
    )


@pytest.mark.asyncio
async def test_profile_returns_hierarchical_roles():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, _test_ruleset(), user_id="jsmith")

    result = response.result
    assert result is not None
    assert result["user_id"] == "jsmith"
    assert result["role_count"] >= 2
    assert len(result["roles"]) >= 2

    # Each role should have duties
    for role in result["roles"]:
        assert "role_id" in role
        assert "duties" in role


@pytest.mark.asyncio
async def test_profile_includes_sod_violations():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, _test_ruleset(), user_id="jsmith")

    assert len(response.result["sod_violations"]) >= 1
    assert response.result["sod_violations"][0]["rule_id"] == "SOD-AP-001"


@pytest.mark.asyncio
async def test_profile_clean_user_no_violations():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, _test_ruleset(), user_id="cleanuser")

    assert response.result is not None
    assert response.result["sod_violations"] == []


@pytest.mark.asyncio
async def test_profile_nonexistent_user():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, _test_ruleset(), user_id="nobody")

    assert response.result is None
    assert any("not found" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_profile_redact_pii():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(
        client, _test_ruleset(), user_id="jsmith", redact_pii=True
    )

    assert response.result["user_name"] != "John Smith"


@pytest.mark.asyncio
async def test_profile_no_ruleset_warns():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, None, user_id="jsmith")

    assert response.result is not None
    assert response.result["sod_violations"] == []
    assert any("No SoD ruleset" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_profile_summary_mode_returns_counts_not_arrays():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(
        client, _test_ruleset(), user_id="jsmith", summary_only=True
    )

    result = response.result
    assert result is not None
    assert result["summary_mode"] is True
    assert result["role_count"] >= 2
    for role in result["roles"]:
        assert isinstance(role["duty_count"], int)
        assert isinstance(role["privilege_count"], int)
        assert role["duties"] == []
        assert role["privileges"] == []


@pytest.mark.asyncio
async def test_profile_summary_mode_still_includes_sod_violations():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(
        client, _test_ruleset(), user_id="jsmith", summary_only=True
    )

    result = response.result
    assert result is not None
    assert "sod_violations" in result
    assert len(result["sod_violations"]) >= 1
    assert result["sod_violations"][0]["rule_id"] == "SOD-AP-001"


@pytest.mark.asyncio
async def test_profile_default_returns_full_hierarchy():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await get_user_security_profile(client, _test_ruleset(), user_id="jsmith")

    result = response.result
    assert result is not None
    assert "summary_mode" not in result
    # At least one role should have duties populated
    has_duties = any(len(role["duties"]) > 0 for role in result["roles"])
    assert has_duties
