"""Live tests for get_licence_summary — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider
from d365fo_security_mcp.tools.summary import get_licence_summary


@pytest.mark.live
class TestLiveSummary:
    """Licence summary report against a real D365 F&O environment."""

    async def test_live_summary_envelope_shape_valid(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Response must have tier_breakdown, total_monthly_cost, total_annual_cost."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        assert "tier_breakdown" in response.result
        assert "total_monthly_cost" in response.result
        assert "total_annual_cost" in response.result
        assert isinstance(response.result["tier_breakdown"], list)
        assert response.metadata.environment != ""

    async def test_live_summary_tier_counts_non_negative(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """All tier counts in the breakdown must be non-negative integers."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        for tier in response.result["tier_breakdown"]:
            assert tier["user_count"] >= 0
            assert tier["monthly_cost"] >= 0

    async def test_live_summary_total_cost_non_negative(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Total costs must be non-negative and annual must equal monthly * 12."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        assert response.result["total_monthly_cost"] >= 0
        assert response.result["total_annual_cost"] >= 0
        assert (
            abs(response.result["total_annual_cost"] - response.result["total_monthly_cost"] * 12)
            < 0.01
        )

    async def test_live_summary_total_users_matches_breakdown(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Sum of tier_breakdown user_counts must equal total_users."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        breakdown_total = sum(t["user_count"] for t in response.result["tier_breakdown"])
        assert breakdown_total == response.result["total_users"]

    async def test_live_summary_user_list_present(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Summary must include a user_list array."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        assert "user_list" in response.result
        assert isinstance(response.result["user_list"], list)

    async def test_live_summary_user_list_count_matches_total(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """user_list length must equal total_users."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        assert len(response.result["user_list"]) == response.result["total_users"]

    async def test_live_summary_user_list_entries_have_required_fields(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Each user_list entry must have all required compact fields."""
        response = await get_licence_summary(live_client, live_tier_config, live_provider)

        required_keys = {"user_id", "user_name", "required_tier", "driving_role", "role_count"}
        for entry in response.result["user_list"]:
            assert required_keys.issubset(entry.keys()), f"Missing keys in {entry}"
