"""Live tests for service account filtering — requires --live flag."""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.assignments import get_all_user_role_assignments
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset
from d365fo_security_mcp.tools.sod.violations import detect_sod_violations

_REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_RULESET_PATH = str(_REPO_ROOT / "examples" / "sod-rules-sample.json")


@pytest.fixture(scope="module")
def sod_ruleset():
    """Load the sample SoD ruleset for live tests."""
    ruleset, _warnings = load_ruleset(SAMPLE_RULESET_PATH)
    return ruleset


@pytest.mark.live
class TestLiveViolationsExcludeServiceAccounts:
    """Service account filtering on SoD violation detection."""

    async def test_live_violations_exclude_service_accounts(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Default exclude_service_accounts=True must populate service_accounts_excluded key."""
        response = await detect_sod_violations(live_client, sod_ruleset)

        assert response.result is not None
        assert "service_accounts_excluded" in response.result
        assert isinstance(response.result["service_accounts_excluded"], int)
        assert response.result["service_accounts_excluded"] >= 0


@pytest.mark.live
class TestLiveAssignmentsExcludeServiceAccounts:
    """Service account filtering on user-role assignments."""

    async def test_live_assignments_exclude_service_accounts(
        self,
        live_client: ODataClient,
    ) -> None:
        """Default exclude_service_accounts=True must populate service_accounts_excluded key."""
        response = await get_all_user_role_assignments(live_client)

        assert response.result is not None
        assert "service_accounts_excluded" in response.result
        assert isinstance(response.result["service_accounts_excluded"], int)
        assert response.result["service_accounts_excluded"] >= 0
