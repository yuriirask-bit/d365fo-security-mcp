"""Tests for d365fo_security_mcp.tools.what_if — what_if_analysis."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.tools.what_if import what_if_analysis


class TestWhatIfAnalysis:
    """Tests for the what_if_analysis tool."""

    async def test_what_if_no_changes_returns_same_tier(self, mock_odata_client, tier_config):
        """When no roles are added or removed the projected tier equals the current."""
        response = await what_if_analysis(mock_odata_client, tier_config, "admin")

        assert response.result["current_tier"]["name"] == response.result["projected_tier"]["name"]
        assert response.result["monthly_delta"] == 0.0
        assert response.result["annual_delta"] == 0.0

    async def test_what_if_add_enterprise_role_upgrades_tier(self, mock_odata_client, tier_config):
        """Adding an Enterprise role to an Activity-only user upgrades the tier."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "warehouse1",
            add_roles=["LEDGERACCOUNTANT"],
        )

        assert response.result["current_tier"]["name"] == "Activity"
        assert response.result["projected_tier"]["name"] == "Enterprise"
        assert response.result["monthly_delta"] > 0

    async def test_what_if_remove_enterprise_role_downgrades_tier(
        self, mock_odata_client, tier_config
    ):
        """Removing the Enterprise role from a mixed user downgrades the tier."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            remove_roles=["LEDGERACCOUNTANT"],
        )

        assert response.result["current_tier"]["name"] == "Enterprise"
        assert response.result["projected_tier"]["name"] == "Activity"
        assert response.result["monthly_delta"] < 0

    async def test_what_if_remove_all_roles_returns_none_tier(self, mock_odata_client, tier_config):
        """Removing all roles drops the user to None tier."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "warehouse1",
            remove_roles=["WHSWAREHOUSEWORKER"],
        )

        assert response.result["projected_tier"]["name"] == "None"
        assert response.result["projected_tier"]["monthly_cost"] == 0.0

    async def test_what_if_annual_delta_is_monthly_times_12(self, mock_odata_client, tier_config):
        """Annual delta should be monthly_delta * 12."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "warehouse1",
            add_roles=["LEDGERACCOUNTANT"],
        )

        expected_annual = round(response.result["monthly_delta"] * 12, 2)
        assert response.result["annual_delta"] == expected_annual

    async def test_what_if_projected_roles_include_added(self, mock_odata_client, tier_config):
        """Added roles should appear in projected_roles."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "warehouse1",
            add_roles=["LEDGERACCOUNTANT"],
        )

        assert "LEDGERACCOUNTANT" in response.result["projected_roles"]
        assert "WHSWAREHOUSEWORKER" in response.result["projected_roles"]

    async def test_what_if_projected_roles_exclude_removed(self, mock_odata_client, tier_config):
        """Removed roles should not appear in projected_roles."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            remove_roles=["LEDGERACCOUNTANT"],
        )

        assert "LEDGERACCOUNTANT" not in response.result["projected_roles"]
        assert "BUDGETBUDGETCLERK" in response.result["projected_roles"]

    async def test_what_if_unrecognised_role_produces_warning(self, mock_odata_client, tier_config):
        """Adding a role that doesn't exist should produce a warning."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "admin",
            add_roles=["NONEXISTENT_ROLE"],
        )

        assert len(response.warnings) > 0
        assert any("NONEXISTENT_ROLE" in w for w in response.warnings)

    async def test_what_if_metadata_has_environment(self, mock_odata_client, tier_config):
        """Response metadata should contain the client environment."""
        response = await what_if_analysis(mock_odata_client, tier_config, "admin")

        assert response.metadata.environment == "test.operations.dynamics.com"

    async def test_what_if_current_roles_matches_active_assignments(
        self, mock_odata_client, tier_config
    ):
        """current_roles should list the user's active role identifiers."""
        response = await what_if_analysis(mock_odata_client, tier_config, "jsmith")

        assert sorted(response.result["current_roles"]) == sorted(
            ["BUDGETBUDGETCLERK", "LEDGERACCOUNTANT"]
        )

    async def test_what_if_cost_delta_calculated_correctly(self, mock_odata_client, tier_config):
        """Removing Enterprise role: delta should be Activity - Enterprise cost."""
        response = await what_if_analysis(
            mock_odata_client,
            tier_config,
            "jsmith",
            remove_roles=["LEDGERACCOUNTANT"],
        )

        # Enterprise=135.70, Activity=25.30 => delta = 25.30 - 135.70 = -110.40
        assert response.result["monthly_delta"] == pytest.approx(-110.40, abs=0.01)
