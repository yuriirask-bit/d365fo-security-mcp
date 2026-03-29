"""Live tests for detect_sod_violations and get_sod_conflict_matrix — requires --live flag."""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.matrix import get_sod_conflict_matrix
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
class TestLiveSodViolations:
    """SoD violation detection against a real D365 F&O environment."""

    async def test_detect_sod_violations_returns_valid_envelope(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await detect_sod_violations(live_client, sod_ruleset)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_detect_sod_violations_result_structure(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Result must contain the expected summary and user-list fields."""
        response = await detect_sod_violations(live_client, sod_ruleset)

        result = response.result
        assert "total_violations" in result
        assert "users_scanned" in result
        assert "users_with_violations" in result
        assert "ruleset_version" in result
        assert "rules_evaluated" in result
        assert "users" in result
        assert isinstance(result["total_violations"], int)
        assert isinstance(result["users_scanned"], int)
        assert isinstance(result["users"], list)

    async def test_detect_sod_violations_single_user_scoping(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Scoping to a single user should scan exactly one user."""
        response = await detect_sod_violations(live_client, sod_ruleset, user_id="Admin")

        # Either the user was found (result populated) or not found (warning)
        if response.result is not None:
            assert response.result["users_scanned"] == 1
        else:
            assert len(response.warnings) >= 1

    async def test_detect_sod_violations_metadata_provider(
        self,
        live_client: ODataClient,
        sod_ruleset,
    ) -> None:
        """Metadata provider must be 'sod'."""
        response = await detect_sod_violations(live_client, sod_ruleset)

        assert response.metadata.provider == "sod"
        assert response.metadata.duration_ms >= 0


@pytest.mark.live
class TestLiveSodConflictMatrix:
    """SoD conflict matrix (ruleset inspection) tests."""

    async def test_get_sod_conflict_matrix_returns_valid_envelope(
        self,
        sod_ruleset,
    ) -> None:
        """Response must have result, metadata, and warnings keys."""
        response = await get_sod_conflict_matrix(sod_ruleset)

        assert response.result is not None
        assert response.metadata is not None
        assert isinstance(response.warnings, list)

    async def test_get_sod_conflict_matrix_contains_rules(
        self,
        sod_ruleset,
    ) -> None:
        """Result must include the rules array and ruleset metadata."""
        response = await get_sod_conflict_matrix(sod_ruleset)

        result = response.result
        assert "ruleset_name" in result
        assert "version" in result
        assert "rule_count" in result
        assert "categories" in result
        assert "rules" in result
        assert isinstance(result["rules"], list)
        assert result["rule_count"] == len(result["rules"])
        assert result["rule_count"] > 0

    async def test_get_sod_conflict_matrix_category_filter(
        self,
        sod_ruleset,
    ) -> None:
        """Filtering by category should return only matching rules."""
        response = await get_sod_conflict_matrix(sod_ruleset, category="accounts_payable")

        result = response.result
        for rule in result["rules"]:
            assert rule["category"] == "accounts_payable"
