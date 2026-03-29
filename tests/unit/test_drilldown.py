"""Tests for d365fo_security_mcp.tools.drilldown — get_role_licence_details."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.tools.drilldown import get_role_licence_details


class TestGetRoleLicenceDetails:
    """Tests for the get_role_licence_details tool."""

    async def test_drilldown_known_role_returns_details(self, mock_odata_client, tier_config):
        """Querying LEDGERACCOUNTANT should return full role details."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        assert response.result is not None
        assert response.result["role_identifier"] == "LEDGERACCOUNTANT"
        assert response.result["role_name"] == "Accountant"

    async def test_drilldown_licence_tier_is_populated(self, mock_odata_client, tier_config):
        """The licence_tier dict should contain name, display_name, costs."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        tier = response.result["licence_tier"]
        assert tier["name"] == "Enterprise"
        assert tier["monthly_cost"] == 135.7
        assert tier["annual_cost"] == pytest.approx(135.7 * 12, abs=0.01)

    async def test_drilldown_duties_are_flat_list(self, mock_odata_client, tier_config):
        """Duties should be a flat list of {duty_identifier, duty_name}."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        # LEDGERACCOUNTANT has 4 duties in the fixture
        assert response.result["duty_count"] == 4
        assert len(response.result["duties"]) == 4
        for duty in response.result["duties"]:
            assert "duty_identifier" in duty
            assert "duty_name" in duty
            # Flat list — no nested privileges
            assert "privileges" not in duty

    async def test_drilldown_privileges_are_flat_list(self, mock_odata_client, tier_config):
        """Privileges should be a separate flat list."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        # LEDGERACCOUNTANT has 6 privileges in the fixture
        assert response.result["privilege_count"] == 6
        assert len(response.result["privileges"]) == 6
        for priv in response.result["privileges"]:
            assert "privilege_identifier" in priv
            assert "privilege_name" in priv

    async def test_drilldown_unknown_role_returns_empty_flat_lists(
        self, mock_odata_client, tier_config
    ):
        """A role that doesn't exist should return empty flat lists with a warning."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "NONEXISTENT_ROLE"
        )

        assert response.result["duties"] == []
        assert response.result["privileges"] == []
        assert response.result["duty_count"] == 0
        assert response.result["privilege_count"] == 0
        assert response.result["licence_tier"] is None
        assert len(response.warnings) == 1
        assert "NONEXISTENT_ROLE" in response.warnings[0]

    async def test_drilldown_activity_role_returns_activity_tier(
        self, mock_odata_client, tier_config
    ):
        """BUDGETBUDGETCLERK should resolve to Activity tier."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "BUDGETBUDGETCLERK"
        )

        assert response.result["licence_tier"]["name"] == "Activity"
        assert response.result["licence_tier"]["monthly_cost"] == 25.3

    async def test_drilldown_universal_role_returns_universal_tier(
        self, mock_odata_client, tier_config
    ):
        """HCMEMPLOYEE should resolve to Universal tier."""
        response = await get_role_licence_details(mock_odata_client, tier_config, "HCMEMPLOYEE")

        assert response.result["licence_tier"]["name"] == "Universal"
        assert response.result["licence_tier"]["monthly_cost"] == 5.8

    async def test_drilldown_metadata_has_environment(self, mock_odata_client, tier_config):
        """Response metadata should contain the client environment."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        assert response.metadata.environment == "test.operations.dynamics.com"

    async def test_drilldown_no_warnings_for_typed_role(self, mock_odata_client, tier_config):
        """A role with a valid UserLicenseType should produce no warnings."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        assert response.warnings == []

    async def test_drilldown_warehouse_worker_duties(self, mock_odata_client, tier_config):
        """WHSWAREHOUSEWORKER should have duties from the fixture."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "WHSWAREHOUSEWORKER"
        )

        assert response.result is not None
        assert response.result["duty_count"] == 2
        duty_ids = [d["duty_identifier"] for d in response.result["duties"]]
        assert "WHSWarehouseWorkMaintain" in duty_ids
        assert "InventTransferOrderReceive" in duty_ids

    async def test_drilldown_warehouse_worker_privileges(self, mock_odata_client, tier_config):
        """WHSWAREHOUSEWORKER should have privileges from the fixture."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "WHSWAREHOUSEWORKER"
        )

        assert response.result["privilege_count"] == 3
        priv_ids = [p["privilege_identifier"] for p in response.result["privileges"]]
        assert "WHSWorkCreateAndClose" in priv_ids
        assert "WHSMobileDeviceView" in priv_ids
        assert "InventTransferOrderReceive" in priv_ids

    async def test_drilldown_display_name_differs_from_internal_name(
        self, mock_odata_client, tier_config
    ):
        """display_name should be a human-readable label distinct from the raw name."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT"
        )

        licence_tier = response.result["licence_tier"]
        assert licence_tier["display_name"] != licence_tier["name"]
        assert len(licence_tier["display_name"]) > 0

    async def test_drilldown_summary_only_omits_privileges(self, mock_odata_client, tier_config):
        """With summary_only=True, privileges is empty list but privilege_count is populated."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT", summary_only=True
        )

        assert response.result["privileges"] == []
        assert response.result["privilege_count"] == 6
        # Duties should still be populated
        assert response.result["duty_count"] == 4
        assert len(response.result["duties"]) == 4

    async def test_drilldown_summary_only_false_includes_privileges(
        self, mock_odata_client, tier_config
    ):
        """With summary_only=False, existing behaviour is unchanged — full privileges returned."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "LEDGERACCOUNTANT", summary_only=False
        )

        assert response.result["privilege_count"] == 6
        assert len(response.result["privileges"]) == 6
        for priv in response.result["privileges"]:
            assert "privilege_identifier" in priv
            assert "privilege_name" in priv

    async def test_drilldown_role_not_found_with_summary_only(self, mock_odata_client, tier_config):
        """Role not found still returns the same shape with summary_only=True."""
        response = await get_role_licence_details(
            mock_odata_client, tier_config, "NONEXISTENT_ROLE", summary_only=True
        )

        assert response.result["duties"] == []
        assert response.result["privileges"] == []
        assert response.result["duty_count"] == 0
        assert response.result["privilege_count"] == 0
        assert response.result["licence_tier"] is None
        assert len(response.warnings) == 1
        assert "NONEXISTENT_ROLE" in response.warnings[0]
