"""Tests for d365fo_security_mcp.tools.under_licensed — detect_under_licensed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from d365fo_security_mcp.tools.under_licensed import detect_under_licensed


class TestDetectUnderLicensedAssessOnly:
    """Tests for detect_under_licensed with assess-only provider."""

    async def test_under_licensed_assess_only_returns_none_result(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Assess-only provider cannot detect under-licensing — result should be None."""
        response = await detect_under_licensed(mock_odata_client, tier_config, assess_only_provider)

        assert response.result is None

    async def test_under_licensed_assess_only_produces_warning(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Assess-only mode should return a warning about needing an external source."""
        response = await detect_under_licensed(mock_odata_client, tier_config, assess_only_provider)

        assert len(response.warnings) == 1
        assert "external licence source" in response.warnings[0].lower()


class TestDetectUnderLicensedLiveMode:
    """Tests for detect_under_licensed with a live licence provider."""

    @staticmethod
    def _make_live_provider(assigned: dict[str, str]) -> MagicMock:
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value=assigned)
        return provider

    async def test_under_licensed_detects_user_below_required_tier(
        self, mock_odata_client, tier_config
    ):
        """A user assigned Activity but needing Enterprise is under-licensed."""
        provider = self._make_live_provider({"admin": "Activity"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        assert response.result["under_licensed_count"] >= 1
        under_ids = [u["user_id"] for u in response.result["users"]]
        assert "admin" in under_ids

    async def test_under_licensed_correctly_licensed_not_flagged(
        self, mock_odata_client, tier_config
    ):
        """A user whose assigned tier matches the required tier is not under-licensed."""
        provider = self._make_live_provider({"admin": "Enterprise"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        under_ids = [u["user_id"] for u in response.result["users"]]
        assert "admin" not in under_ids

    async def test_under_licensed_user_has_enforcement_risk(self, mock_odata_client, tier_config):
        """Under-licensed users should carry an enforcement_risk field."""
        provider = self._make_live_provider({"admin": "Activity"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        for user in response.result["users"]:
            assert "enforcement_risk" in user

    async def test_under_licensed_user_has_tier_gap(self, mock_odata_client, tier_config):
        """Under-licensed users should have a tier_gap string with arrow."""
        provider = self._make_live_provider({"admin": "Activity"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        admin_entry = [u for u in response.result["users"] if u["user_id"] == "admin"][0]
        assert "\u2192" in admin_entry["tier_gap"]

    async def test_under_licensed_unknown_user_produces_warning(
        self, mock_odata_client, tier_config
    ):
        """Users in assessments but missing from provider data produce a warning."""
        provider = self._make_live_provider({"admin": "Enterprise"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        assert len(response.warnings) > 0
        assert any("unknown" in w.lower() for w in response.warnings)

    async def test_under_licensed_metadata_provider(self, mock_odata_client, tier_config):
        """Metadata should reflect the live provider name."""
        provider = self._make_live_provider({"admin": "Enterprise"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        assert response.metadata.provider == "graph"

    async def test_under_licensed_over_licensed_user_not_flagged(
        self, mock_odata_client, tier_config
    ):
        """A user assigned a HIGHER tier than required should NOT be under-licensed."""
        provider = self._make_live_provider({"warehouse1": "Enterprise"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        under_ids = [u["user_id"] for u in response.result["users"]]
        assert "warehouse1" not in under_ids

    async def test_under_licensed_tier_gap_shows_display_names(
        self, mock_odata_client, tier_config
    ):
        """tier_gap should show display names, with Activity on the left."""
        provider = self._make_live_provider({"admin": "Activity"})

        response = await detect_under_licensed(mock_odata_client, tier_config, provider)

        admin_entry = [u for u in response.result["users"] if u["user_id"] == "admin"][0]
        parts = [p.strip() for p in admin_entry["tier_gap"].split("\u2192")]
        assert len(parts) == 2
        assert parts[0]  # assigned display name non-empty
        assert parts[1]  # required display name non-empty


class TestUnderLicensedStaleWarning:
    """Tests for stale data warnings on under_licensed (FR-014)."""

    @staticmethod
    def _make_live_provider(assigned: dict[str, str], last_sync: datetime) -> MagicMock:
        provider = MagicMock()
        provider.provider_name.return_value = "graph"
        provider.get_assigned_licences = AsyncMock(return_value=assigned)
        provider.last_sync_time = last_sync
        return provider

    async def test_under_licensed_fresh_data_no_stale_warning(self, mock_odata_client, tier_config):
        provider = self._make_live_provider({"admin": "Enterprise"}, datetime.now(timezone.utc))

        response = await detect_under_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=7
        )

        assert response.result["warning"] is None

    async def test_under_licensed_stale_data_includes_warning(self, mock_odata_client, tier_config):
        provider = self._make_live_provider(
            {"admin": "Enterprise"}, datetime.now(timezone.utc) - timedelta(days=10)
        )

        response = await detect_under_licensed(
            mock_odata_client, tier_config, provider, stale_threshold_days=7
        )

        assert response.result["warning"] is not None
        assert "stale" in response.result["warning"].lower()

    async def test_under_licensed_assess_only_skips_stale_check(
        self, mock_odata_client, tier_config, assess_only_provider
    ):
        """Assess-only returns None result — no stale warning needed."""
        response = await detect_under_licensed(
            mock_odata_client, tier_config, assess_only_provider, stale_threshold_days=7
        )

        assert response.result is None
