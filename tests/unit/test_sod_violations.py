"""Unit tests for detect_sod_violations tool."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.tools.sod.violations import detect_sod_violations

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixtures() -> dict:
    return json.loads((_FIXTURES / "sod_test_users.json").read_text())


def _make_client(fixtures: dict) -> MagicMock:
    """Create a mock OData client returning fixture data."""
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


def _load_test_ruleset(fixtures: dict) -> SodRuleset:
    """Build a ruleset from fixtures inline."""
    from d365fo_security_mcp.models.sod import (
        SodConflictRule,
        SodRuleset,
        SodRulesetMetadata,
    )

    raw = fixtures["sod_rules"]
    rules = [SodConflictRule.model_validate(r) for r in raw["rules"]]
    return SodRuleset(
        metadata=SodRulesetMetadata(
            name=raw["metadata"]["name"],
            version=raw["metadata"]["version"],
            rule_count=len(rules),
            category_count=len({r.category for r in rules}),
        ),
        rules=rules,
    )


@pytest.mark.asyncio
async def test_detect_sod_violations_finds_violating_user():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset)

    result = response.result
    assert result is not None
    assert result["total_violations"] >= 1
    assert result["users_scanned"] == 3

    # jsmith has APClerk (VendTableMaintain) + PaymentMgr (VendPaymProposalApprove)
    violating_users = {u["user_id"] for u in result["users"]}
    assert "jsmith" in violating_users


@pytest.mark.asyncio
async def test_detect_sod_violations_clean_user_not_flagged():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset)

    violating_ids = {u["user_id"] for u in response.result["users"]}
    assert "cleanuser" not in violating_ids


@pytest.mark.asyncio
async def test_detect_sod_violations_single_user_scope():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset, user_id="jsmith")

    assert response.result is not None
    assert response.result["users_scanned"] == 1
    assert len(response.result["users"]) == 1
    assert response.result["users"][0]["user_id"] == "jsmith"


@pytest.mark.asyncio
async def test_detect_sod_violations_nonexistent_user():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset, user_id="nobody")

    assert response.result is None
    assert any("not found" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_detect_sod_violations_no_ruleset():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)

    response = await detect_sod_violations(client, None)

    assert response.result is None
    assert any("No SoD ruleset configured" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_detect_sod_violations_redact_pii():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset, redact_pii=True)

    for user in response.result["users"]:
        # Redacted names should not match original
        assert user["user_name"] != "John Smith"
        assert user["user_name"] != "Alice Clerk"


@pytest.mark.asyncio
async def test_detect_sod_violations_includes_metadata():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset)

    assert response.metadata.provider == "sod"
    assert response.metadata.environment == "test.operations.dynamics.com"
    assert response.metadata.duration_ms >= 0


@pytest.mark.asyncio
async def test_detect_sod_violations_violation_details():
    fixtures = _load_fixtures()
    client = _make_client(fixtures)
    ruleset = _load_test_ruleset(fixtures)

    response = await detect_sod_violations(client, ruleset, user_id="jsmith")

    violation = response.result["users"][0]["violations"][0]
    assert violation["rule_id"] == "SOD-AP-001"
    assert violation["risk_level"] == "Critical"
    assert "VendTableMaintain" in violation["matched_duties_a"]
    assert "VendPaymProposalApprove" in violation["matched_duties_b"]
    assert "APClerk" in violation["granting_roles_a"]
    assert "PaymentMgr" in violation["granting_roles_b"]
