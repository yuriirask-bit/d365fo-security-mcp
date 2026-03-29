"""Live tests for what-if SoD projection — requires --live flag."""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset
from d365fo_security_mcp.tools.what_if import what_if_analysis

_REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_RULESET_PATH = str(_REPO_ROOT / "examples" / "sod-rules-sample.json")


async def _first_user_id(client: ODataClient, tier_config: LicenceTierConfig) -> str:
    """Return the first user ID from a live assessment."""
    response = await assess_all_users(client, tier_config)
    assessments = response.result.get("assessments", [])
    if not assessments:
        pytest.skip("No users found in the live environment")
    return assessments[0]["user_id"]


@pytest.mark.live
class TestLiveWhatIfSod:
    """What-if SoD projection against a real D365 F&O environment."""

    async def test_live_what_if_includes_sod_impact(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
    ) -> None:
        """With a ruleset, result must contain sod_impact; without, must warn."""
        user_id = await _first_user_id(live_client, live_tier_config)

        # Load the sample ruleset
        ruleset, _warnings = load_ruleset(SAMPLE_RULESET_PATH)

        response = await what_if_analysis(
            live_client,
            live_tier_config,
            user_id,
            add_roles=["SystemAdministrator"],
            remove_roles=[],
            ruleset=ruleset,
        )

        assert response.result is not None
        assert "sod_impact" in response.result

        sod_impact = response.result["sod_impact"]
        assert "current_violations" in sod_impact
        assert "projected_violations" in sod_impact
        assert "net_change" in sod_impact
        assert "new_violations" in sod_impact
        assert "resolved_violations" in sod_impact
        assert isinstance(sod_impact["current_violations"], int)
        assert isinstance(sod_impact["projected_violations"], int)

    async def test_live_what_if_no_ruleset_warns(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
    ) -> None:
        """Without a ruleset, sod_impact must be absent and a warning emitted."""
        user_id = await _first_user_id(live_client, live_tier_config)

        response = await what_if_analysis(
            live_client,
            live_tier_config,
            user_id,
            add_roles=["SystemAdministrator"],
            remove_roles=[],
            ruleset=None,
        )

        assert response.result is not None
        assert "sod_impact" not in response.result
        assert any("ruleset" in w.lower() for w in response.warnings)
