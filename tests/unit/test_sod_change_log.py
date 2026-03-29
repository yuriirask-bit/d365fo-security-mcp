"""Unit tests for security change log via App Insights customEvents."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from d365fo_security_mcp.tools.sod.change_log import get_security_change_log


def _make_client() -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"
    return client


@pytest.mark.asyncio
async def test_change_log_returns_entries():
    """Changes from App Insights customEvents are returned."""
    client = _make_client()

    mock_rows = [
        {
            "timestamp": "2026-03-20T10:00:00Z",
            "ChangeType": "Added",
            "UserId": "jsmith",
            "SecurityRoleId": "APClerk",
            "SecurityRoleName": "AP Clerk",
            "ChangedBy": "admin",
        },
        {
            "timestamp": "2026-03-25T14:00:00Z",
            "ChangeType": "Removed",
            "UserId": "jsmith",
            "SecurityRoleId": "APClerk",
            "SecurityRoleName": "AP Clerk",
            "ChangedBy": "admin",
        },
    ]

    with patch(
        "d365fo_security_mcp.tools.sod.change_log.query_app_insights",
        new_callable=AsyncMock,
        return_value=(mock_rows, []),
    ):
        response = await get_security_change_log(
            client,
            days=30,
            tenant_id="t",
            client_id="c",
            client_secret="s",
            app_insights_connection_string="ApplicationId=test",
        )

    assert response.result is not None
    assert response.result["total_changes"] == 2
    assert response.result["source"] == "AppInsights/customEvents"
    assert response.result["changes"][0]["user_id"] == "jsmith"
    assert response.result["changes"][0]["change_type"] == "Added"


@pytest.mark.asyncio
async def test_change_log_empty_result():
    """No events in date range produces a warning."""
    client = _make_client()

    with patch(
        "d365fo_security_mcp.tools.sod.change_log.query_app_insights",
        new_callable=AsyncMock,
        return_value=([], []),
    ):
        response = await get_security_change_log(
            client,
            days=7,
            tenant_id="t",
            client_id="c",
            client_secret="s",
            app_insights_connection_string="ApplicationId=test",
        )

    assert response.result["total_changes"] == 0
    assert any("No role assignment changes" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_change_log_app_insights_not_configured():
    """No connection string returns empty with setup guidance."""
    client = _make_client()

    response = await get_security_change_log(client, days=30)

    assert response.result["total_changes"] == 0
    assert any("APP_INSIGHTS_CONNECTION_STRING" in w for w in response.warnings)


@pytest.mark.asyncio
async def test_change_log_user_filter():
    """User filter is included in the KQL query."""
    client = _make_client()
    captured_kql = None

    async def _mock_query(tid, cid, cs, conn, kql, **kwargs):
        nonlocal captured_kql
        captured_kql = kql
        return [], []

    with patch(
        "d365fo_security_mcp.tools.sod.change_log.query_app_insights",
        side_effect=_mock_query,
    ):
        await get_security_change_log(
            client,
            days=30,
            user_id="jsmith",
            tenant_id="t",
            client_id="c",
            client_secret="s",
            app_insights_connection_string="ApplicationId=test",
        )

    assert captured_kql is not None
    assert "jsmith" in captured_kql


@pytest.mark.asyncio
async def test_change_log_redact_pii_hashes_changed_by():
    """PII redaction hashes the changed_by field."""
    client = _make_client()

    mock_rows = [
        {
            "timestamp": "2026-03-20T10:00:00Z",
            "ChangeType": "Added",
            "UserId": "jsmith",
            "SecurityRoleId": "APClerk",
            "SecurityRoleName": "AP Clerk",
            "ChangedBy": "admin",
        },
    ]

    with patch(
        "d365fo_security_mcp.tools.sod.change_log.query_app_insights",
        new_callable=AsyncMock,
        return_value=(mock_rows, []),
    ):
        response = await get_security_change_log(
            client,
            days=30,
            redact_pii=True,
            tenant_id="t",
            client_id="c",
            client_secret="s",
            app_insights_connection_string="ApplicationId=test",
        )

    changed_by = response.result["changes"][0]["changed_by"]
    assert changed_by != "admin"
    assert len(changed_by) == 12


@pytest.mark.asyncio
async def test_change_log_no_azure_ad_credentials():
    """Connection string set but no Azure AD creds returns warning."""
    client = _make_client()

    response = await get_security_change_log(
        client,
        days=30,
        app_insights_connection_string="ApplicationId=test",
    )

    assert response.result["total_changes"] == 0
    assert any("Azure AD credentials" in w for w in response.warnings)
