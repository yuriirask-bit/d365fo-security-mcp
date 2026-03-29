"""Unit tests for three-source login activity module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from d365fo_security_mcp.tools.sod.app_insights import parse_connection_string
from d365fo_security_mcp.tools.sod.login_activity import get_login_activity

_SAMPLE_CONN_STR = (
    "InstrumentationKey=00000000-0000-0000-0000-000000000001;"
    "IngestionEndpoint=https://test-region.in.applicationinsights.azure.com/;"
    "LiveEndpoint=https://test-region.livediagnostics.monitor.azure.com/;"
    "ApplicationId=00000000-0000-0000-0000-000000000002"
)


def _make_client(
    *,
    dblog_data: list | None = None,
    dblog_error: bool = False,
) -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    async def _query(entity: str, **kwargs):
        if entity == "DatabaseLogs":
            if dblog_error:
                raise RuntimeError("Entity unavailable")
            return dblog_data or []
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


def _make_graph_response():
    """Empty Graph response so it doesn't error during tests."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"value": []}
    return resp


def _make_app_insights_response(rows: list) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "tables": [
            {
                "columns": [
                    {"name": "user_Id"},
                    {"name": "LastLogin"},
                ],
                "rows": rows,
            }
        ]
    }
    return resp


def _make_http_mock(*, app_insights_resp=None, graph_resp=None):
    """Build an httpx.AsyncClient mock supporting both .post and .get."""
    if graph_resp is None:
        graph_resp = _make_graph_response()

    async def _mock_post(url, **kwargs):
        return app_insights_resp

    async def _mock_get(url, **kwargs):
        return graph_resp

    mock_http = AsyncMock()
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=False)
    mock_http.post = _mock_post
    mock_http.get = _mock_get
    return mock_http


def _make_msal_mock(*, succeed=True):
    """Build msal module mock."""
    mock_app = MagicMock()
    if succeed:
        mock_app.acquire_token_for_client.return_value = {"access_token": "fake-token"}
    else:
        mock_app.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "bad credentials",
        }
    mock_mod = MagicMock()
    mock_mod.ConfidentialClientApplication.return_value = mock_app
    return mock_mod


def testparse_connection_string():
    parsed = parse_connection_string(_SAMPLE_CONN_STR)
    assert parsed["ApplicationId"] == "00000000-0000-0000-0000-000000000002"
    assert "InstrumentationKey" in parsed


def testparse_connection_string_empty():
    parsed = parse_connection_string("")
    assert parsed == {}


@pytest.mark.asyncio
async def test_login_activity_no_sources_available():
    client = _make_client(dblog_error=True)

    result, warnings = await get_login_activity(client)

    assert result == {}
    assert any("No login activity data" in w for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_app_insights_not_configured():
    """When no connection string is set, no App Insights config warning."""
    client = _make_client()

    result, warnings = await get_login_activity(client)

    # Should not get an ApplicationId or auth warning
    assert not any("ApplicationId" in w for w in warnings)
    assert not any("authentication failed" in w.lower() for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_app_insights_source():
    """App Insights returns login data via KQL query."""
    client = _make_client()
    ai_resp = _make_app_insights_response(
        [
            ["Admin", "2026-03-27T11:28:23Z"],
            ["jsmith", "2026-03-26T09:15:00Z"],
        ]
    )
    mock_http = _make_http_mock(app_insights_resp=ai_resp)
    mock_msal = _make_msal_mock()

    with (
        patch.dict("sys.modules", {"msal": mock_msal}),
        patch("httpx.AsyncClient", return_value=mock_http),
    ):
        result, warnings = await get_login_activity(
            client,
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            app_insights_connection_string=_SAMPLE_CONN_STR,
        )

    assert "admin" in result
    assert result["admin"].year == 2026
    assert "jsmith" in result


@pytest.mark.asyncio
async def test_login_activity_app_insights_missing_app_id():
    """Connection string without ApplicationId emits a warning."""
    client = _make_client()
    mock_msal = _make_msal_mock()
    mock_http = _make_http_mock(app_insights_resp=MagicMock())

    with (
        patch.dict("sys.modules", {"msal": mock_msal}),
        patch("httpx.AsyncClient", return_value=mock_http),
    ):
        result, warnings = await get_login_activity(
            client,
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            app_insights_connection_string="InstrumentationKey=xxx",
        )

    assert any("ApplicationId" in w for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_app_insights_auth_failure():
    """MSAL auth failure for App Insights emits a warning."""
    client = _make_client()
    mock_msal = _make_msal_mock(succeed=False)
    mock_http = _make_http_mock(app_insights_resp=MagicMock())

    with (
        patch.dict("sys.modules", {"msal": mock_msal}),
        patch("httpx.AsyncClient", return_value=mock_http),
    ):
        result, warnings = await get_login_activity(
            client,
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            app_insights_connection_string=_SAMPLE_CONN_STR,
        )

    assert any("authentication failed" in w.lower() for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_app_insights_needs_azure_ad_creds():
    """App Insights skipped with warning when connection string set but no creds."""
    client = _make_client()

    result, warnings = await get_login_activity(
        client,
        app_insights_connection_string=_SAMPLE_CONN_STR,
        # No tenant_id/client_id/client_secret
    )

    assert any("Azure AD credentials missing" in w for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_no_graph_credentials():
    client = _make_client()

    result, warnings = await get_login_activity(client)

    assert any("Graph credentials not configured" in w for w in warnings)


@pytest.mark.asyncio
async def test_login_activity_merge_takes_latest():
    """When multiple sources have data, most recent wins."""
    client = _make_client(
        dblog_data=[
            {
                "TableName": "SysUserLog",
                "NewValue": "jsmith",
                "CreatedDateTime": "2026-03-15T10:00:00Z",
            },
        ],
    )

    # App Insights returns an older timestamp
    ai_resp = _make_app_insights_response(
        [
            ["jsmith", "2026-01-01T00:00:00Z"],
        ]
    )
    mock_http = _make_http_mock(app_insights_resp=ai_resp)
    mock_msal = _make_msal_mock()

    with (
        patch.dict("sys.modules", {"msal": mock_msal}),
        patch("httpx.AsyncClient", return_value=mock_http),
    ):
        result, _ = await get_login_activity(
            client,
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            app_insights_connection_string=_SAMPLE_CONN_STR,
        )

    assert "jsmith" in result
    # March 15 from DatabaseLogs should win over Jan 1 from App Insights
    assert result["jsmith"].month == 3
