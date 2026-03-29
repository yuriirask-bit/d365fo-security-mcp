"""Tests for SoD projection in what_if_analysis."""

from __future__ import annotations

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodDutyGroup,
    SodRuleset,
    SodRulesetMetadata,
)
from d365fo_security_mcp.tools.what_if import what_if_analysis


def _make_ruleset(rules: list[SodConflictRule] | None = None) -> SodRuleset:
    """Build a minimal SodRuleset for testing."""
    return SodRuleset(
        metadata=SodRulesetMetadata(
            name="Test SoD Rules",
            version="1.0",
            rule_count=len(rules) if rules else 0,
            category_count=1,
        ),
        rules=rules or [],
    )


# Rule: conflict between LEDGERACCOUNTANT duty and BUDGETBUDGETCLERK duty
CONFLICT_RULE = SodConflictRule(
    id="SOD-TEST-001",
    name="Journal posting vs budget entry",
    category="general_ledger",
    risk_level="High",
    description="A user should not maintain journals and budget entries.",
    duty_group_a=SodDutyGroup(
        name="Maintain journals",
        duties=["LedgerJournalsMaintain"],
    ),
    duty_group_b=SodDutyGroup(
        name="Maintain budget entries",
        duties=["BudgetBudgetRegisterEntriesMaintain"],
    ),
)

# Rule: conflict between warehouse duties (used for no-change scenario)
WAREHOUSE_RULE = SodConflictRule(
    id="SOD-TEST-002",
    name="Warehouse work vs transfer receive",
    category="inventory",
    risk_level="Medium",
    description="Test rule for warehouse.",
    duty_group_a=SodDutyGroup(
        name="Maintain warehouse work",
        duties=["WHSWarehouseWorkMaintain"],
    ),
    duty_group_b=SodDutyGroup(
        name="Receive transfers",
        duties=["InventTransferOrderReceive"],
    ),
)


class TestWhatIfSod:
    """Tests for SoD projection in what_if_analysis."""

    async def test_what_if_sod_new_violations_detected(self, mock_odata_client, tier_config):
        """Adding BUDGETBUDGETCLERK to a user with LEDGERACCOUNTANT triggers a new SoD violation."""
        ruleset = _make_ruleset([CONFLICT_RULE])

        # warehouse1 has only WHSWAREHOUSEWORKER — add both conflicting roles
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "warehouse1",
            add_roles=["LEDGERACCOUNTANT", "BUDGETBUDGETCLERK"],
            ruleset=ruleset,
        )

        sod = response.result["sod_impact"]
        assert sod["current_violations"] == 0
        assert sod["projected_violations"] == 1
        assert sod["net_change"] == 1
        assert len(sod["new_violations"]) == 1
        assert sod["new_violations"][0]["rule_id"] == "SOD-TEST-001"
        assert len(sod["resolved_violations"]) == 0

    async def test_what_if_sod_violations_resolved(self, mock_odata_client, tier_config):
        """Removing BUDGETBUDGETCLERK from jsmith resolves the SoD conflict."""
        ruleset = _make_ruleset([CONFLICT_RULE])

        # jsmith has LEDGERACCOUNTANT + BUDGETBUDGETCLERK — remove the budget role
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            remove_roles=["BUDGETBUDGETCLERK"],
            ruleset=ruleset,
        )

        sod = response.result["sod_impact"]
        assert sod["current_violations"] == 1
        assert sod["projected_violations"] == 0
        assert sod["net_change"] == -1
        assert len(sod["new_violations"]) == 0
        assert len(sod["resolved_violations"]) == 1
        assert sod["resolved_violations"][0]["rule_id"] == "SOD-TEST-001"

    async def test_what_if_sod_no_change(self, mock_odata_client, tier_config):
        """Adding a role that doesn't create new conflicts keeps net_change=0."""
        ruleset = _make_ruleset([CONFLICT_RULE])

        # jsmith already has both conflicting roles — adding warehouse doesn't change SoD
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            add_roles=["WHSWAREHOUSEWORKER"],
            ruleset=ruleset,
        )

        sod = response.result["sod_impact"]
        assert sod["net_change"] == 0
        assert len(sod["new_violations"]) == 0
        assert len(sod["resolved_violations"]) == 0

    async def test_what_if_sod_no_ruleset(self, mock_odata_client, tier_config):
        """When ruleset is None, sod_impact is absent and a warning is emitted."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            ruleset=None,
        )

        assert "sod_impact" not in response.result
        assert any("no ruleset" in w.lower() for w in response.warnings)
