from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.summary import get_licence_summary


@pytest.fixture
def file_provider_mixed():
    """Provider with a mix of tiers — some users are over-licensed."""
    provider = MagicMock()
    provider.provider_name.return_value = "file"
    provider.get_assigned_licences = AsyncMock(
        return_value={
            "jsmith": "Enterprise",
            "aclerk": "Enterprise",
            "warehouse1": "Activity",
            "employee1": "Universal",
        }
    )
    return provider


@pytest.mark.asyncio
async def test_summary_tier_breakdown_counts_correct(
    mock_odata_client, tier_config, assess_only_provider
):
    response = await get_licence_summary(mock_odata_client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None
    assert "tier_breakdown" in result

    tier_breakdown = result["tier_breakdown"]
    assert isinstance(tier_breakdown, list)
    assert len(tier_breakdown) > 0

    breakdown_total = sum(entry["user_count"] for entry in tier_breakdown)
    assert breakdown_total == result["total_users"]


@pytest.mark.asyncio
async def test_summary_total_cost_matches_sum_of_tiers(
    mock_odata_client, tier_config, assess_only_provider
):
    response = await get_licence_summary(mock_odata_client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None

    tier_breakdown = result["tier_breakdown"]
    computed_total = sum(entry["monthly_cost"] for entry in tier_breakdown)
    assert result["total_monthly_cost"] == pytest.approx(computed_total, abs=0.01)


@pytest.mark.asyncio
async def test_summary_includes_over_under_counts_when_provider_available(
    mock_odata_client, tier_config, file_provider_mixed
):
    response = await get_licence_summary(mock_odata_client, tier_config, file_provider_mixed)
    result = response.result
    assert result is not None

    assert "over_licensed_count" in result
    assert result["over_licensed_count"] is not None
    assert result["over_licensed_count"] >= 0


@pytest.mark.asyncio
async def test_summary_savings_opportunity_calculated(
    mock_odata_client, tier_config, file_provider_mixed
):
    response = await get_licence_summary(mock_odata_client, tier_config, file_provider_mixed)
    result = response.result
    assert result is not None

    assert "savings_opportunity" in result
    assert result["savings_opportunity"] is not None
    assert result["savings_opportunity"] > 0


@pytest.mark.asyncio
async def test_summary_assess_only_omits_over_under_counts(
    mock_odata_client, tier_config, assess_only_provider
):
    response = await get_licence_summary(mock_odata_client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None

    assert result["over_licensed_count"] is None
    assert result["under_licensed_count"] is None


# ---------------------------------------------------------------------------
# user_list tests (T009)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_user_list_present_with_fields(
    mock_odata_client, tier_config, assess_only_provider
):
    """user_list should exist and each entry should have the five compact fields."""
    response = await get_licence_summary(mock_odata_client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None

    assert "user_list" in result
    user_list = result["user_list"]
    assert isinstance(user_list, list)
    assert len(user_list) == result["total_users"]

    expected_keys = {"user_id", "user_name", "required_tier", "driving_role", "role_count"}
    for entry in user_list:
        assert set(entry.keys()) == expected_keys


@pytest.mark.asyncio
async def test_summary_user_list_sorted_by_tier_then_name(
    mock_odata_client, tier_config, assess_only_provider
):
    """user_list should be sorted by tier priority descending, then user_name ascending."""
    response = await get_licence_summary(mock_odata_client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None

    user_list = result["user_list"]
    assert len(user_list) > 1

    # Verify ordering: build (priority, name) tuples and check they are sorted
    # We need to map display_name back to tier name to get priority
    display_to_name: dict[str, str] = {}
    for tier in tier_config.tiers:
        display_to_name[tier.display_name] = tier.name
    # Also handle "No licence required" for None tier
    display_to_name["No licence required"] = "None"

    pairs = []
    for entry in user_list:
        tier_name = display_to_name.get(entry["required_tier"], "None")
        priority = tier_config.priority(tier_name)
        pairs.append((-priority, entry["user_name"].lower()))

    assert pairs == sorted(pairs), "user_list is not sorted by tier priority desc, then name asc"


@pytest.mark.asyncio
async def test_summary_empty_environment_returns_empty_list(tier_config, assess_only_provider):
    """An environment with no users should produce an empty user_list."""

    async def _empty_query(entity: str, **kwargs):
        return []

    client = MagicMock()
    client.query = AsyncMock(side_effect=_empty_query)
    client.environment = "empty.operations.dynamics.com"

    response = await get_licence_summary(client, tier_config, assess_only_provider)
    result = response.result
    assert result is not None

    assert result["user_list"] == []
    assert result["total_users"] == 0


@pytest.mark.asyncio
async def test_summary_user_list_redact_pii_hashes_fields(
    mock_odata_client, tier_config, assess_only_provider
):
    """When redact_pii=True, user_id values in user_list should be hashed (not original)."""
    response = await get_licence_summary(
        mock_odata_client, tier_config, assess_only_provider, redact_pii=True
    )
    result = response.result
    assert result is not None

    user_list = result["user_list"]
    assert len(user_list) > 0

    # The original user ids from fixture data
    original_ids = {
        "admin",
        "jsmith",
        "aclerk",
        "warehouse1",
        "employee1",
        "manager1",
        "noroles",
        "svcaccount",
        "multiuser",
        "teamonly",
    }

    for entry in user_list:
        # Hashed values should NOT match any original user_id
        assert entry["user_id"] not in original_ids, (
            f"user_id '{entry['user_id']}' was not redacted"
        )
        # Hashed values should be 12-char hex strings
        assert len(entry["user_id"]) == 12


@pytest.mark.asyncio
async def test_summary_user_list_at_least_60pct_smaller_than_full_assess(
    mock_odata_client, tier_config, assess_only_provider
):
    """SC-004: compact user_list payload is at least 60% smaller than full assessment."""
    # Full assessment with roles included
    full_response = await assess_all_users(mock_odata_client, tier_config, include_roles=True)
    full_payload_size = len(json.dumps(full_response.result, default=str))

    # Summary report with compact user_list
    summary_response = await get_licence_summary(
        mock_odata_client, tier_config, assess_only_provider
    )
    user_list_size = len(json.dumps(summary_response.result["user_list"], default=str))

    # user_list should be at least 60% smaller than full assessments payload
    assert user_list_size < full_payload_size * 0.4, (
        f"user_list ({user_list_size} bytes) is not 60%+ smaller than "
        f"full assessment ({full_payload_size} bytes)"
    )
