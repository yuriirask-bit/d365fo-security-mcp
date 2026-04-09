"""Live tests for security change log KQL query against App Insights.

Requires:
- APP_INSIGHTS_CONNECTION_STRING in .env
- Azure AD credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
- Monitoring Reader RBAC role on the App Insights resource
- SMCPSecurityRoleEventHandler X++ class deployed (for non-empty results)
"""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.change_log import _build_kql, get_security_change_log


@pytest.mark.live
class TestLiveChangeLogQuery:
    """Security change log KQL execution against a real App Insights instance."""

    async def test_change_log_no_auth_warnings(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """Query executes without auth or permission warnings."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await get_security_change_log(
            live_client,
            days=30,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        auth_warnings = [
            w
            for w in response.warnings
            if "auth" in w.lower() or "403" in w or "credential" in w.lower()
        ]
        assert auth_warnings == [], f"Unexpected auth warnings: {auth_warnings}"

    async def test_change_log_returns_valid_envelope(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """Response has the expected result structure."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await get_security_change_log(
            live_client,
            days=30,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        result = response.result
        assert result is not None
        assert "total_changes" in result
        assert "period_days" in result
        assert "changes" in result
        assert isinstance(result["changes"], list)
        assert result["period_days"] == 30
        assert result["source"] == "AppInsights/customEvents"
        assert response.metadata.provider == "sod"
        assert response.metadata.duration_ms >= 0

    async def test_change_log_entry_fields(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """Each change entry has all required fields with correct types."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await get_security_change_log(
            live_client,
            days=90,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        if not response.result["changes"]:
            pytest.skip(
                "No role assignment changes in the last 90 days — "
                "X++ event handler may not be deployed"
            )

        for entry in response.result["changes"]:
            assert "timestamp" in entry
            assert "user_id" in entry
            assert "role_id" in entry
            assert "role_name" in entry
            assert "change_type" in entry
            assert "changed_by" in entry
            assert entry["change_type"] in ("Added", "Removed")

    async def test_change_log_user_filter_narrows_results(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """Filtering by user_id returns only that user's changes."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        # First get all changes to find a user to filter on
        all_response = await get_security_change_log(
            live_client,
            days=90,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        if not all_response.result["changes"]:
            pytest.skip("No role changes to filter on")

        target_user = all_response.result["changes"][0]["user_id"]

        filtered_response = await get_security_change_log(
            live_client,
            days=90,
            user_id=target_user,
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        for entry in filtered_response.result["changes"]:
            assert entry["user_id"] == target_user, (
                f"Expected user_id '{target_user}' but got '{entry['user_id']}'"
            )

        assert filtered_response.result["total_changes"] <= all_response.result["total_changes"]


@pytest.mark.live
class TestLiveChangeLogKqlExecution:
    """Verify generated KQL executes successfully against real App Insights."""

    async def test_kql_with_user_filter_is_valid(
        self,
        live_client: ODataClient,
        live_profile: D365Profile,
        live_server_config: ServerConfig,
    ) -> None:
        """KQL with user filter executes without query syntax errors."""
        if not live_server_config.app_insights_connection_string:
            pytest.skip("APP_INSIGHTS_CONNECTION_STRING not configured")

        response = await get_security_change_log(
            live_client,
            days=7,
            user_id="nonexistent_test_user",
            tenant_id=live_profile.tenant_id,
            client_id=live_profile.client_id,
            client_secret=live_profile.client_secret,
            app_insights_connection_string=live_server_config.app_insights_connection_string,
        )

        # Query should succeed (no auth/syntax errors) even with zero results
        query_error_warnings = [w for w in response.warnings if "failed" in w.lower() or "403" in w]
        assert query_error_warnings == [], f"KQL execution failed: {query_error_warnings}"
        assert response.result["total_changes"] == 0


class TestChangeLogKqlStructure:
    """Verify KQL template optimisations (no live credentials needed)."""

    def test_kql_template_has_timestamp_filter_first(self) -> None:
        """Verify the KQL puts timestamp filter before name filter (perf)."""
        kql = _build_kql(30)
        timestamp_pos = kql.index("timestamp >= ago")
        name_pos = kql.index("name has_any")
        assert timestamp_pos < name_pos, "timestamp filter must come before name filter"

    def test_kql_template_uses_has_any(self) -> None:
        """Verify the KQL uses has_any instead of in for name filtering."""
        kql = _build_kql(30)
        assert "has_any" in kql
        assert "| where name in (" not in kql

    def test_kql_template_extends_cd_once(self) -> None:
        """Verify customDimensions is extended once as cd alias."""
        kql = _build_kql(30)
        assert "extend cd = customDimensions" in kql
        # Should not reference customDimensions directly after the extend
        after_extend = kql.split("extend cd = customDimensions")[1]
        assert "customDimensions" not in after_extend

    def test_kql_user_filter_uses_cd_alias(self) -> None:
        """User filter should reference cd.UserId, not customDimensions."""
        kql = _build_kql(30, user_id="testuser")
        assert "cd.UserId" in kql
        assert "customDimensions.UserId" not in kql
