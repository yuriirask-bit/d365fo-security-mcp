"""Live tests for assess_user_licence_requirements — requires --live flag."""

from __future__ import annotations

import time

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users, assess_user


@pytest.mark.live
class TestLiveAssessAllUsers:
    """Full-environment assessment against a real D365 F&O environment."""

    async def test_live_assess_all_users_returns_non_empty_list(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Environment must have at least one user."""
        response = await assess_all_users(live_client, live_tier_config)

        assert response.result["total_users"] > 0
        assert len(response.result["assessments"]) == response.result["total_users"]

    async def test_live_assess_all_users_envelope_shape_valid(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """ToolResponse envelope must have result, metadata, warnings keys."""
        response = await assess_all_users(live_client, live_tier_config)

        assert "total_users" in response.result
        assert "assessments" in response.result
        assert response.metadata.environment != ""
        assert response.metadata.duration_ms >= 0
        assert isinstance(response.warnings, list)

    async def test_live_assess_all_users_each_assessment_has_required_fields(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Every assessment in the list must carry required fields."""
        response = await assess_all_users(live_client, live_tier_config)

        for assessment in response.result["assessments"]:
            assert "user_id" in assessment
            assert "required_tier" in assessment
            assert "role_count" in assessment
            assert "roles" in assessment
            assert "driving_role" in assessment
            assert assessment["required_tier"] is not None
            assert "name" in assessment["required_tier"]
            assert "monthly_cost" in assessment["required_tier"]

    async def test_live_assess_all_users_completes_within_60s(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Full-environment scan must complete in under 60 seconds (SC-005)."""
        start = time.monotonic()
        await assess_all_users(live_client, live_tier_config)
        elapsed = time.monotonic() - start

        assert elapsed < 60, f"Full scan took {elapsed:.1f}s — exceeds 60s limit (SC-005)"

    async def test_live_assess_all_users_tier_names_are_known(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """All returned tier names must be recognised by LicenceTierConfig."""
        response = await assess_all_users(live_client, live_tier_config)
        known_names = {t.name for t in live_tier_config.tiers}

        for assessment in response.result["assessments"]:
            tier_name = assessment["required_tier"]["name"]
            assert tier_name in known_names, (
                f"Unknown tier '{tier_name}' for user '{assessment['user_id']}'"
            )


@pytest.mark.live
class TestLiveAssessSingleUser:
    """Single-user assessment against a real D365 F&O environment."""

    async def _get_first_user_id(self, client: ODataClient, tier_config: LicenceTierConfig) -> str:
        """Helper: fetch all users and return the first user_id."""
        response = await assess_all_users(client, tier_config)
        assessments = response.result["assessments"]
        if not assessments:
            pytest.skip("No users found in the live environment")
        return assessments[0]["user_id"]

    async def test_live_assess_single_user_returns_correct_shape(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Single-user response must carry user_id, required_tier, roles."""
        user_id = await self._get_first_user_id(live_client, live_tier_config)
        response = await assess_user(live_client, live_tier_config, user_id)

        assert response.result["user_id"] == user_id
        assert response.result["required_tier"] is not None
        assert isinstance(response.result["roles"], list)
        assert isinstance(response.result["role_count"], int)

    async def test_live_assess_single_user_completes_within_2s(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Single-user assessment must complete in under 2 seconds (SC-004)."""
        user_id = await self._get_first_user_id(live_client, live_tier_config)

        start = time.monotonic()
        await assess_user(live_client, live_tier_config, user_id)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"Single-user assess took {elapsed:.2f}s — exceeds 2s limit (SC-004)"


@pytest.mark.live
class TestLiveAssessFiltering:
    """Filtering and compact mode against a real D365 F&O environment."""

    async def test_live_assess_tier_filter_returns_subset(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """tier_filter should return only users matching the specified tier."""
        # First get all users to find a tier that exists
        all_response = await assess_all_users(live_client, live_tier_config)
        assessments = all_response.result["assessments"]
        if not assessments:
            pytest.skip("No users found in the live environment")

        # Pick the tier of the first user
        target_tier = assessments[0]["required_tier"]["name"]

        filtered = await assess_all_users(live_client, live_tier_config, tier_filter=target_tier)

        for a in filtered.result["assessments"]:
            assert a["required_tier"]["name"] == target_tier

    async def test_live_assess_include_roles_false_omits_roles(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """include_roles=False should return assessments without the roles array."""
        response = await assess_all_users(live_client, live_tier_config, include_roles=False)

        for a in response.result["assessments"]:
            assert "roles" not in a
            assert "user_id" in a
            assert "role_count" in a

    async def test_live_assess_include_roles_true_includes_roles(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """include_roles=True should return assessments with the roles array."""
        response = await assess_all_users(live_client, live_tier_config, include_roles=True)

        for a in response.result["assessments"]:
            assert "roles" in a
            assert isinstance(a["roles"], list)

    async def test_live_assess_invalid_tier_filter_returns_empty_with_warning(
        self, live_client: ODataClient, live_tier_config: LicenceTierConfig
    ) -> None:
        """Invalid tier_filter should return empty assessments and a warning."""
        response = await assess_all_users(
            live_client, live_tier_config, tier_filter="InvalidTierName"
        )

        assert response.result["total_users"] == 0
        assert len(response.result["assessments"]) == 0
        assert any("Invalid tier_filter" in w for w in response.warnings)
