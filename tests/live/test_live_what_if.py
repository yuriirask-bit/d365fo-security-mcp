"""Live tests for what_if_analysis — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.what_if import what_if_analysis


async def _first_user_id(client: ODataClient, tier_config: LicenceTierConfig) -> str:
    """Return the first user ID from a live assessment."""
    response = await assess_all_users(client, tier_config)
    assessments = response.result.get("assessments", [])
    if not assessments:
        pytest.skip("No users found in the live environment")
    return assessments[0]["user_id"]


@pytest.mark.live
class TestLiveWhatIf:
    """What-if role change analysis against a real D365 F&O environment."""

    async def test_live_what_if_no_change_returns_zero_delta(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Simulating no role changes must return zero monthly and annual delta."""
        user_id = await _first_user_id(live_client, live_tier_config)
        response = await what_if_analysis(
            live_client, live_tier_config, user_id, add_roles=[], remove_roles=[]
        )

        assert response.result["monthly_delta"] == 0.0
        assert response.result["annual_delta"] == 0.0

    async def test_live_what_if_no_change_current_equals_projected_tier(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """With no role changes, current_tier and projected_tier must match."""
        user_id = await _first_user_id(live_client, live_tier_config)
        response = await what_if_analysis(
            live_client, live_tier_config, user_id, add_roles=[], remove_roles=[]
        )

        assert response.result["current_tier"]["name"] == response.result["projected_tier"]["name"]

    async def test_live_what_if_envelope_shape_valid(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Response must carry user_id, current_tier, projected_tier, deltas, roles."""
        user_id = await _first_user_id(live_client, live_tier_config)
        response = await what_if_analysis(
            live_client, live_tier_config, user_id, add_roles=[], remove_roles=[]
        )

        assert response.result["user_id"] == user_id
        assert "current_tier" in response.result
        assert "projected_tier" in response.result
        assert "monthly_delta" in response.result
        assert "annual_delta" in response.result
        assert "current_roles" in response.result
        assert "projected_roles" in response.result
        assert response.metadata.environment != ""
        assert isinstance(response.warnings, list)

    async def test_live_what_if_invalid_role_produces_warning(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Adding a non-existent role must produce a warning, not raise an exception."""
        user_id = await _first_user_id(live_client, live_tier_config)
        response = await what_if_analysis(
            live_client,
            live_tier_config,
            user_id,
            add_roles=["ROLE_THAT_DOES_NOT_EXIST_XYZ"],
            remove_roles=[],
        )

        assert len(response.warnings) > 0
