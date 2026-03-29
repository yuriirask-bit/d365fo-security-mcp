"""Live tests for App Insights login activity integration.

Requires:
- APP_INSIGHTS_CONNECTION_STRING in .env
- Monitoring Reader RBAC role on the App Insights resource
- At least one user session in App Insights pageViews data
"""

from __future__ import annotations

from pathlib import Path

import pytest

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.dormant import find_dormant_privileged_accounts
from d365fo_security_mcp.tools.sod.login_activity import get_login_activity
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset

_REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_RULESET_PATH = str(_REPO_ROOT / "examples" / "sod-rules-sample.json")


@pytest.fixture(scope="module")
def sod_ruleset():
    ruleset, _warnings = load_ruleset(SAMPLE_RULESET_PATH)
    return ruleset


@pytest.mark.live
class TestLiveAppInsightsLoginActivity:
    """App Insights pageViews as a login data source."""

    async def test_app_insights_returns_login_data(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """App Insights source returns at least one user login."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        login_data, warnings = await get_login_activity(
            live_client,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            graph_scope=live_server_config.graph_scope,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        # Should have data from at least App Insights
        assert len(login_data) > 0, f"Expected login data but got none. Warnings: {warnings}"

    async def test_app_insights_no_auth_warnings(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """No App Insights auth/permission warnings when properly configured."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        _login_data, warnings = await get_login_activity(
            live_client,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            graph_scope=live_server_config.graph_scope,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        ai_warnings = [w for w in warnings if "App Insights" in w]
        assert ai_warnings == [], f"Unexpected App Insights warnings: {ai_warnings}"

    async def test_app_insights_admin_has_login(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """Admin user should have a login timestamp from App Insights."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        login_data, _warnings = await get_login_activity(
            live_client,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            graph_scope=live_server_config.graph_scope,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        assert "admin" in login_data, (
            f"Expected 'admin' in login data keys: {list(login_data.keys())}"
        )


@pytest.mark.live
class TestLiveDormantWithAppInsights:
    """Dormant account detection using App Insights login data."""

    async def test_dormant_uses_app_insights_login_data(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
        sod_ruleset,
    ) -> None:
        """Admin should NOT be dormant when App Insights has their login."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await find_dormant_privileged_accounts(
            live_client,
            sod_ruleset,
            days=90,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            graph_scope=live_server_config.graph_scope,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        result = response.result
        dormant_ids = [u["user_id"] for u in result["users"]]
        assert "Admin" not in dormant_ids and "admin" not in dormant_ids, (
            "Admin user was flagged as dormant despite App Insights login data"
        )

    async def test_dormant_service_accounts_excluded_count(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
        sod_ruleset,
    ) -> None:
        """Service account filtering should exclude a reasonable number."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await find_dormant_privileged_accounts(
            live_client,
            sod_ruleset,
            days=90,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            graph_scope=live_server_config.graph_scope,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        result = response.result
        excluded = result.get("service_accounts_excluded", 0)
        checked = result.get("privileged_users_checked", 0)

        # Sanity: excluded should be much less than total users
        assert excluded < 50, (
            f"Too many accounts excluded ({excluded}) — NetworkDomain filter may be misconfigured"
        )
        assert checked > 0, "No privileged users checked"
