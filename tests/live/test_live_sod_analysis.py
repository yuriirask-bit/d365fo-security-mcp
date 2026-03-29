"""Live tests for get_user_security_profile, get_high_risk_users, get_role_duty_tree."""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.high_risk import get_high_risk_users
from d365fo_security_mcp.tools.sod.profile import get_user_security_profile
from d365fo_security_mcp.tools.sod.role_tree import get_role_duty_tree
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset

_REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_RULESET_PATH = str(_REPO_ROOT / "examples" / "sod-rules-sample.json")


@pytest.fixture(scope="module")
def sod_ruleset():
    """Load the sample SoD ruleset for live tests."""
    ruleset, _warnings = load_ruleset(SAMPLE_RULESET_PATH)
    return ruleset


@pytest.mark.live
class TestLiveUserSecurityProfile:
    """User security profile against a real D365 F&O environment."""

    async def test_profile_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await get_user_security_profile(live_client, sod_ruleset, user_id="Admin")

        assert response.metadata is not None
        assert isinstance(response.warnings, list)
        # Admin may or may not exist; either result or warning is valid
        if response.result is not None:
            assert response.metadata.provider == "sod"

    async def test_profile_hierarchical_data(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Profile result must contain hierarchical role/duty structure."""
        response = await get_user_security_profile(live_client, sod_ruleset, user_id="Admin")

        if response.result is None:
            pytest.skip("Admin user not found in this environment")

        result = response.result
        assert "user_id" in result
        assert "user_name" in result
        assert "role_count" in result
        assert "roles" in result
        assert "sod_violations" in result
        assert isinstance(result["roles"], list)
        assert isinstance(result["sod_violations"], list)

        # Each role should have duties structure
        if result["roles"]:
            role = result["roles"][0]
            assert "role_id" in role
            assert "role_name" in role
            assert "duties" in role

    async def test_profile_not_found_user(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """A non-existent user should return None result with a warning."""
        response = await get_user_security_profile(
            live_client, sod_ruleset, user_id="NONEXISTENT_USER_ID_12345"
        )

        assert response.result is None
        assert len(response.warnings) >= 1


@pytest.mark.live
class TestLiveHighRiskUsers:
    """High risk user ranking against a real D365 F&O environment."""

    async def test_high_risk_users_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await get_high_risk_users(live_client, sod_ruleset)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_high_risk_users_result_structure(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must contain count, scanned total, and users list."""
        response = await get_high_risk_users(live_client, sod_ruleset)

        result = response.result
        assert "high_risk_count" in result
        assert "users_scanned" in result
        assert "users" in result
        assert isinstance(result["high_risk_count"], int)
        assert isinstance(result["users_scanned"], int)
        assert isinstance(result["users"], list)

    async def test_high_risk_users_top_limit(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Top parameter should limit returned users."""
        response = await get_high_risk_users(live_client, sod_ruleset, top=3)

        result = response.result
        assert len(result["users"]) <= 3


@pytest.mark.live
class TestLiveRoleDutyTree:
    """Role duty tree against a real D365 F&O environment."""

    async def test_role_duty_tree_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        # Try -SYSADMIN- first, fall back to SYSTEMUSER
        response = await get_role_duty_tree(live_client, sod_ruleset, role="-SYSADMIN-")

        if response.result is None:
            response = await get_role_duty_tree(live_client, sod_ruleset, role="SYSTEMUSER")

        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_role_duty_tree_structure(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must contain role info, duties, and sub-roles."""
        response = await get_role_duty_tree(live_client, sod_ruleset, role="-SYSADMIN-")

        if response.result is None:
            response = await get_role_duty_tree(live_client, sod_ruleset, role="SYSTEMUSER")

        if response.result is None:
            pytest.skip("Neither -SYSADMIN- nor SYSTEMUSER role found")

        result = response.result
        assert "role_id" in result
        assert "role_name" in result
        assert "duty_count" in result
        assert "duties" in result
        assert "sub_roles" in result
        assert isinstance(result["duties"], list)
        assert isinstance(result["sub_roles"], list)

    async def test_role_duty_tree_not_found(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """A non-existent role should return None result with a warning."""
        response = await get_role_duty_tree(live_client, sod_ruleset, role="NONEXISTENT_ROLE_XYZ")

        assert response.result is None
        assert len(response.warnings) >= 1
