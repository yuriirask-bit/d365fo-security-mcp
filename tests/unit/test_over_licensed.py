"""Tests for d365fo_security_mcp.tools.over_licensed — detect_over_licensed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.over_licensed import detect_over_licensed


class TestDetectOverLicensedAssessOnly:
    """Tests for detect_over_licensed in assess-only (projection) mode."""

    async def test_over_licensed_assess_only_mode_returns_projection(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Assess-only provider should return mode='projection'."""
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        assert response.result["mode"] == "projection"

    async def test_over_licensed_assess_only_savings_are_zero(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """In assess-only mode, monthly/annual savings per user are always 0."""
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        for user in response.result["users"]:
            assert user["monthly_savings"] == 0.0
            assert user["annual_savings"] == 0.0

    async def test_over_licensed_assess_only_excludes_zero_cost_tiers(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Users at zero-cost tiers (None, SelfServe, Server) should be excluded."""
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        user_ids = [u["user_id"] for u in response.result["users"]]
        # svcaccount is on None tier (cost 0) — should NOT be in the list
        assert "svcaccount" not in user_ids
        # noroles has None tier — should NOT be in the list
        assert "noroles" not in user_ids

    async def test_over_licensed_assess_only_includes_paid_users(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Users on paid tiers should appear in projection mode."""
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        user_ids = [u["user_id"] for u in response.result["users"]]
        # admin is Enterprise (135.70) — should be included
        assert "admin" in user_ids

    async def test_over_licensed_assess_only_metadata_provider(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Metadata should reflect the assess-only provider."""
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        assert response.metadata.provider == "assess-only"


class TestDetectOverLicensedLiveMode:
    """Tests for detect_over_licensed with a live licence provider."""

    @staticmethod
    def _make_live_provider(assigned: dict[str, str]) -> MagicMock:
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value=assigned)
        return provider

    async def test_over_licensed_live_detects_over_licensed_user(
        self, mock_odata_client, tier_config
    ):
        """A user assigned Enterprise but needing only Activity is over-licensed."""
        provider = self._make_live_provider({"warehouse1": "Enterprise", "admin": "Enterprise"})

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        assert response.result["mode"] == "live"
        over_users = {u["user_id"]: u for u in response.result["users"]}
        assert "warehouse1" in over_users
        assert over_users["warehouse1"]["assigned_tier"] == "Enterprise"
        assert over_users["warehouse1"]["required_tier"] == "Activity"
        assert over_users["warehouse1"]["monthly_savings"] > 0

    async def test_over_licensed_live_correctly_licensed_not_flagged(
        self, mock_odata_client, tier_config
    ):
        """A user whose assigned tier matches the required tier is not over-licensed."""
        provider = self._make_live_provider({"admin": "Enterprise"})

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        over_user_ids = [u["user_id"] for u in response.result["users"]]
        assert "admin" not in over_user_ids

    async def test_over_licensed_live_unmatched_user_produces_warning(
        self, mock_odata_client, tier_config
    ):
        """Users in assessments but not in provider data produce a warning."""
        provider = self._make_live_provider({})

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        assert len(response.warnings) > 0
        assert any("unmatched" in w.lower() for w in response.warnings)

    async def test_over_licensed_live_annual_savings_calculation(
        self, mock_odata_client, tier_config
    ):
        """Annual savings should be monthly_savings * 12."""
        provider = self._make_live_provider({"warehouse1": "Enterprise"})

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        for user in response.result["users"]:
            assert user["annual_savings"] == round(user["monthly_savings"] * 12, 2)

    async def test_over_licensed_live_total_annual_savings(self, mock_odata_client, tier_config):
        """total_annual_savings should be the sum of individual monthly_savings * 12."""
        provider = self._make_live_provider(
            {
                "warehouse1": "Enterprise",
                "employee1": "Enterprise",
                "admin": "Enterprise",
            }
        )

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        total_monthly = sum(u["monthly_savings"] for u in response.result["users"])
        assert response.result["total_annual_savings"] == round(total_monthly * 12, 2)

    async def test_over_licensed_live_savings_amount_correct(self, mock_odata_client, tier_config):
        """Enterprise(135.70) - Activity(25.30) = 110.40 monthly savings."""
        provider = self._make_live_provider({"warehouse1": "Enterprise", "admin": "Enterprise"})

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        wh_entry = next(u for u in response.result["users"] if u["user_id"] == "warehouse1")
        assert wh_entry["monthly_savings"] == pytest.approx(110.40, abs=0.01)


class TestOverLicensedProjectionWarning:
    """Tests for the projection mode warning (FR-013)."""

    async def test_over_licensed_assess_only_includes_warning(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        response = await detect_over_licensed(mock_odata_client, tier_config, assess_only_provider)

        assert response.result["warning"] is not None
        assert "No external licence source configured" in response.result["warning"]
        assert "get_security_server_config" in response.result["warning"]

    async def test_over_licensed_live_mode_warning_null(self, mock_odata_client, tier_config):
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value={"admin": "Enterprise"})
        provider.last_sync_time = datetime.now(timezone.utc)

        response = await detect_over_licensed(mock_odata_client, tier_config, provider)

        assert response.result["warning"] is None


class TestOverLicensedStaleWarning:
    """Tests for stale data warnings (FR-014)."""

    async def test_over_licensed_fresh_data_no_stale_warning(self, mock_odata_client, tier_config):
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value={"admin": "Enterprise"})
        provider.last_sync_time = datetime.now(timezone.utc)

        response = await detect_over_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=7
        )

        assert response.result["warning"] is None

    async def test_over_licensed_stale_data_includes_warning(self, mock_odata_client, tier_config):
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value={"admin": "Enterprise"})
        provider.last_sync_time = datetime.now(timezone.utc) - timedelta(days=10)

        response = await detect_over_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=7
        )

        assert response.result["warning"] is not None
        assert "stale" in response.result["warning"].lower()

    async def test_over_licensed_stale_threshold_configurable(self, mock_odata_client, tier_config):
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value={"admin": "Enterprise"})
        provider.last_sync_time = datetime.now(timezone.utc) - timedelta(days=5)

        # 3-day threshold → data is stale
        response = await detect_over_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=3
        )
        assert response.result["warning"] is not None

        # 7-day threshold → data is fresh
        response = await detect_over_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=7
        )
        assert response.result["warning"] is None

    async def test_over_licensed_assess_only_skips_stale_check(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        response = await detect_over_licensed(
            mock_odata_client, tier_config, assess_only_provider, stale_threshold_days=7
        )

        # Should have the projection warning, not a stale warning
        assert "No external licence source configured" in response.result["warning"]
