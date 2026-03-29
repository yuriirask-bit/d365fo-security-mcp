"""Live tests for get_all_user_role_assignments, run_user_access_review, health score."""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.access_review import run_user_access_review
from d365fo_security_mcp.tools.sod.assignments import get_all_user_role_assignments
from d365fo_security_mcp.tools.sod.health_score import get_security_health_score
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset

_REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_RULESET_PATH = str(_REPO_ROOT / "examples" / "sod-rules-sample.json")


@pytest.fixture(scope="module")
def sod_ruleset():
    """Load the sample SoD ruleset for live tests."""
    ruleset, _warnings = load_ruleset(SAMPLE_RULESET_PATH)
    return ruleset


@pytest.mark.live
class TestLiveAllUserRoleAssignments:
    """User role assignment matrix against a real D365 F&O environment."""

    async def test_assignments_returns_valid_envelope(
        self,
        live_client: ODataClient,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await get_all_user_role_assignments(live_client)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_assignments_result_structure(
        self,
        live_client: ODataClient,
    ) -> None:
        """Result must contain total users, total assignments, and users list."""
        response = await get_all_user_role_assignments(live_client)

        result = response.result
        assert "total_users" in result
        assert "total_assignments" in result
        assert "users" in result
        assert isinstance(result["total_users"], int)
        assert isinstance(result["total_assignments"], int)
        assert isinstance(result["users"], list)
        assert result["total_users"] > 0

    async def test_assignments_user_entry_structure(
        self,
        live_client: ODataClient,
    ) -> None:
        """Each user entry must have user_id, user_name, role_count, and roles."""
        response = await get_all_user_role_assignments(live_client)

        users = response.result["users"]
        assert len(users) > 0

        user = users[0]
        assert "user_id" in user
        assert "user_name" in user
        assert "role_count" in user
        assert "roles" in user
        assert isinstance(user["roles"], list)

    async def test_assignments_active_only_filter(
        self,
        live_client: ODataClient,
    ) -> None:
        """Active-only filter should return a valid response."""
        response = await get_all_user_role_assignments(live_client, active_only=True)

        assert response.result is not None
        assert response.result["total_users"] >= 0


@pytest.mark.live
class TestLiveUserAccessReview:
    """User access review against a real D365 F&O environment."""

    async def test_access_review_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await run_user_access_review(live_client, sod_ruleset)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_access_review_result_structure(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must contain total users, SoD violation count, and users list."""
        response = await run_user_access_review(live_client, sod_ruleset)

        result = response.result
        assert "total_users" in result
        assert "users_with_sod_violations" in result
        assert "users" in result
        assert isinstance(result["total_users"], int)
        assert isinstance(result["users"], list)

    async def test_access_review_user_entry_has_sod_flags(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Each user entry must include SoD violation flags."""
        response = await run_user_access_review(live_client, sod_ruleset)

        users = response.result["users"]
        assert len(users) > 0

        user = users[0]
        assert "user_id" in user
        assert "user_name" in user
        assert "role_count" in user
        assert "roles" in user
        assert "has_sod_violations" in user
        assert "sod_violation_count" in user
        assert isinstance(user["has_sod_violations"], bool)
        assert isinstance(user["sod_violation_count"], int)


@pytest.mark.live
class TestLiveSecurityHealthScore:
    """Security health score against a real D365 F&O environment."""

    async def test_health_score_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await get_security_health_score(live_client, sod_ruleset)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_health_score_overall_range(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Overall score must be between 0 and 100."""
        response = await get_security_health_score(live_client, sod_ruleset)

        result = response.result
        assert "overall_score" in result
        assert 0 <= result["overall_score"] <= 100

    async def test_health_score_has_rating(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must include a human-readable rating string."""
        response = await get_security_health_score(live_client, sod_ruleset)

        result = response.result
        assert "rating" in result
        assert result["rating"] in ("Excellent", "Good", "Needs Attention", "Critical")

    async def test_health_score_four_dimensions(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must include exactly 4 scoring dimensions."""
        response = await get_security_health_score(live_client, sod_ruleset)

        result = response.result
        assert "dimensions" in result

        dims = result["dimensions"]
        expected_keys = {
            "sod_compliance",
            "dormant_accounts",
            "role_hygiene",
            "data_completeness",
        }
        assert set(dims.keys()) == expected_keys

        for key in expected_keys:
            dim = dims[key]
            assert "name" in dim
            assert "score" in dim
            assert "status" in dim
            assert "detail" in dim
            assert isinstance(dim["score"], int)
            assert 0 <= dim["score"] <= 25

    async def test_health_score_has_recommendations(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must include a recommendations list."""
        response = await get_security_health_score(live_client, sod_ruleset)

        result = response.result
        assert "recommendations" in result
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) >= 1
