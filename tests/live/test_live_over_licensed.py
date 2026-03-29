"""Live tests for detect_over_licensed_users — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.over_licensed import detect_over_licensed
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider


@pytest.mark.live
class TestLiveOverLicensed:
    """Over-licensed detection in assess-only mode against a real D365 environment."""

    async def test_live_over_licensed_assess_only_returns_projection_mode(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Assess-only mode must set metadata.mode to 'projection'."""
        response = await detect_over_licensed(live_client, live_tier_config, live_provider)

        assert response.result["mode"] == "projection"

    async def test_live_over_licensed_envelope_shape_valid(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Response envelope must contain over_licensed_count, total_annual_savings, users."""
        response = await detect_over_licensed(live_client, live_tier_config, live_provider)

        assert "over_licensed_count" in response.result
        assert "total_annual_savings" in response.result
        assert "users" in response.result
        assert isinstance(response.result["users"], list)
        assert isinstance(response.warnings, list)

    async def test_live_over_licensed_savings_non_negative(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Savings figures must never be negative."""
        response = await detect_over_licensed(live_client, live_tier_config, live_provider)

        assert response.result["total_annual_savings"] >= 0
        for user in response.result["users"]:
            assert user["annual_savings"] >= 0

    async def test_live_over_licensed_user_entries_have_required_fields(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Each over-licensed user entry must have user_id, required_tier, and savings fields."""
        response = await detect_over_licensed(live_client, live_tier_config, live_provider)

        for user in response.result["users"]:
            assert "user_id" in user
            assert "required_tier" in user
            assert "monthly_savings" in user
            assert "annual_savings" in user

    async def test_live_over_licensed_assess_only_has_projection_warning(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Projection mode must include a top-level warning field (FR-013)."""
        response = await detect_over_licensed(live_client, live_tier_config, live_provider)

        assert "warning" in response.result
        assert response.result["warning"] is not None
        assert "get_security_server_config" in response.result["warning"]
