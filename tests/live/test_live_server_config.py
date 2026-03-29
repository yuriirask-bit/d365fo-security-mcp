"""Live tests for get_security_server_config — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.licence_source import get_security_server_config
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider


@pytest.mark.live
class TestLiveServerConfig:
    """Server config introspection against a real D365 F&O environment."""

    async def test_live_server_config_returns_valid_envelope(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Response must have all top-level config sections."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        result = response.result
        assert "server_version" in result
        assert "environment" in result
        assert "licence_source" in result
        assert "capabilities" in result
        assert "limitations" in result

    async def test_live_server_config_environment_has_connectivity(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Environment section must show connectivity true against a real D365 environment."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        env = response.result["environment"]
        assert env["connectivity"] is True
        assert env["base_url"] == live_profile.base_url

    async def test_live_server_config_capabilities_map_complete(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Capabilities map must contain all 8 tool names."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        caps = response.result["capabilities"]
        expected_tools = [
            "assess_user_licence_requirements",
            "detect_over_licensed_users",
            "detect_under_licensed_users",
            "what_if_role_change",
            "get_role_licence_breakdown",
            "get_licence_summary_report",
            "get_security_server_config",
            "validate_licence_source",
        ]
        for tool_name in expected_tools:
            assert tool_name in caps, f"Missing capability: {tool_name}"

    async def test_live_server_config_assess_only_shows_limitations(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Assess-only mode should list limitations for detect_under and detect_over."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        assert response.result["capabilities"]["detect_under_licensed_users"] is False
        assert len(response.result["limitations"]) >= 1

    async def test_live_server_config_available_sources_listed(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Available sources must include graph, ppac, and file."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        sources = response.result["licence_source"]["available_sources"]
        assert "graph" in sources
        assert "ppac" in sources
        assert "file" in sources

    async def test_live_server_config_versions_detected(
        self,
        live_client: ODataClient,
        live_provider: AssessOnlyProvider,
        live_profile: D365Profile,
    ) -> None:
        """Versions should be detected via OData actions against a real D365 environment."""
        import re

        config = ServerConfig()  # type: ignore[call-arg]
        response = await get_security_server_config(
            live_client, config, live_provider, live_profile
        )

        versions = response.result["environment"]["versions"]
        assert "application" in versions
        assert "platform" in versions
        assert "build" in versions

        version_re = re.compile(r"\d+\.\d+\.\d+")
        for key in ("application", "platform", "build"):
            val = versions[key]
            if val is not None:
                assert version_re.match(val), (
                    f"versions.{key} '{val}' does not match expected pattern"
                )
