"""Live tests for get_role_licence_details — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.drilldown import get_role_licence_details


async def _first_enterprise_role(client: ODataClient, tier_config: LicenceTierConfig) -> str:
    """Return the identifier of the first role driving an Enterprise-tier user."""
    response = await assess_all_users(client, tier_config)
    for assessment in response.result.get("assessments", []):
        if assessment["required_tier"]["name"] == "Enterprise" and assessment["driving_role"]:
            return assessment["driving_role"]
    pytest.skip("No Enterprise-tier users found in the live environment")


@pytest.mark.live
class TestLiveDrilldown:
    """Role licence drill-down against a real D365 F&O environment."""

    async def test_live_drilldown_known_role_returns_duties(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """An Enterprise-tier role must return a valid duties list."""
        role_id = await _first_enterprise_role(live_client, live_tier_config)
        response = await get_role_licence_details(live_client, live_tier_config, role_id)

        assert response.result is not None
        assert isinstance(response.result["duties"], list)
        assert isinstance(response.result["privileges"], list)

    async def test_live_drilldown_envelope_shape_valid(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Response must carry role_identifier, licence_tier, duties, privileges."""
        role_id = await _first_enterprise_role(live_client, live_tier_config)
        response = await get_role_licence_details(live_client, live_tier_config, role_id)

        assert "role_identifier" in response.result
        assert "licence_tier" in response.result
        assert "duties" in response.result
        assert "privileges" in response.result
        assert "duty_count" in response.result
        assert "privilege_count" in response.result
        assert response.result["role_identifier"] == role_id
        assert response.metadata.environment != ""
        assert isinstance(response.warnings, list)

    async def test_live_drilldown_invalid_role_returns_empty_lists(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """A non-existent role identifier must return empty flat lists without raising."""
        response = await get_role_licence_details(
            live_client, live_tier_config, "ROLE_DOES_NOT_EXIST_XYZ"
        )

        assert response.result["duties"] == []
        assert response.result["privileges"] == []

    async def test_live_drilldown_duties_have_required_fields(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Each duty must carry duty_identifier and duty_name (flat structure)."""
        role_id = await _first_enterprise_role(live_client, live_tier_config)
        response = await get_role_licence_details(live_client, live_tier_config, role_id)

        for duty in response.result["duties"]:
            assert "duty_identifier" in duty
            assert "duty_name" in duty

        for priv in response.result["privileges"]:
            assert "privilege_identifier" in priv
            assert "privilege_name" in priv

    async def test_live_drilldown_summary_only_omits_privileges(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """summary_only=True returns duties without privileges for a known role."""
        role_id = await _first_enterprise_role(live_client, live_tier_config)
        response = await get_role_licence_details(
            live_client, live_tier_config, role_id, summary_only=True
        )

        assert response.result is not None
        assert isinstance(response.result["duties"], list)
        # Key assertion: privileges omitted in summary mode
        assert response.result["privileges"] == []
        assert isinstance(response.result["privilege_count"], int)
        assert isinstance(response.result["duty_count"], int)
