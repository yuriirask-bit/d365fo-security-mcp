"""Unit tests for d365fo_security_mcp.tools.licence_source."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.tools.licence_source import (
    _detect_versions,
    get_security_server_config,
    validate_licence_source,
)
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider
from d365fo_security_mcp.tools.providers.file_provider import FileProvider

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_profile() -> D365Profile:
    """Return a D365Profile with test values."""
    return D365Profile(
        D365FO_BASE_URL="https://test.operations.dynamics.com",
        D365FO_TENANT_ID="test-tenant-id",
        D365FO_CLIENT_ID="test-client-id",
        D365FO_CLIENT_SECRET="test-client-secret",
    )


@pytest.fixture
def mock_server_config() -> ServerConfig:
    """Return a default ServerConfig."""
    return ServerConfig()


def _make_call_action_mock(
    app: str = "10.0.46",
    platform: str = "7.0.7778.29",
    build: str = "10.0.2428.63",
) -> AsyncMock:
    """Create a mock call_action that returns version strings by action name."""
    action_map = {
        "GetApplicationVersion": app,
        "GetPlatformBuildVersion": platform,
        "GetApplicationBuildVersion": build,
    }

    async def _call_action(action_name: str, entity_set: str = "DataManagementEntities") -> str:
        return action_map.get(action_name, "")

    return AsyncMock(side_effect=_call_action)


@pytest.fixture
def mock_client_success() -> MagicMock:
    """OData client that successfully returns data."""
    client = MagicMock()
    client.query = AsyncMock(return_value=[{"SecurityRoleIdentifier": "SysAdmin"}])
    client.call_action = _make_call_action_mock()
    return client


@pytest.fixture
def mock_client_failure() -> MagicMock:
    """OData client whose query raises an exception."""
    client = MagicMock()
    client.query = AsyncMock(side_effect=Exception("connection refused"))
    client.call_action = AsyncMock(side_effect=Exception("connection refused"))
    return client


@pytest.fixture
def graph_provider() -> MagicMock:
    """Provider that reports its name as 'graph'."""
    provider = MagicMock()
    provider.provider_name.return_value = "graph"
    return provider


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.2.3")
async def test_server_config_no_source_shows_detect_under_false(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """AssessOnlyProvider: detect_under_licensed_users=False, limitations populated."""
    provider = AssessOnlyProvider()
    # Clear env to avoid extra limitations from detected credentials
    with patch.dict("os.environ", {}, clear=True):
        response = await get_security_server_config(
            mock_client_success, mock_server_config, provider, mock_profile
        )
    result = response.result
    assert result is not None

    assert result["capabilities"]["detect_under_licensed_users"] is False
    assert len(result["limitations"]) == 2
    assert "detect_under_licensed_users unavailable" in result["limitations"][0]
    assert "projection mode" in result["limitations"][1]


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.2.3")
async def test_server_config_graph_source_shows_all_capabilities_true(
    _mock_version, mock_client_success, mock_server_config, mock_profile, graph_provider
):
    """When provider_name is 'graph', all capabilities are True and limitations is empty."""
    response = await get_security_server_config(
        mock_client_success, mock_server_config, graph_provider, mock_profile
    )
    result = response.result
    assert result is not None

    for tool_name, enabled in result["capabilities"].items():
        assert enabled is True, f"{tool_name} should be True for graph provider"
    assert result["limitations"] == []


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.2.3")
async def test_server_config_environment_populated(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """base_url comes from profile; connectivity and versions from OData."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_success, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None

    env = result["environment"]
    assert env["base_url"] == "https://test.operations.dynamics.com"
    assert env["connectivity"] is True
    versions = env["versions"]
    assert versions["application"] == "10.0.46"
    assert versions["platform"] == "7.0.7778.29"
    assert versions["build"] == "10.0.2428.63"


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.2.3")
async def test_server_config_environment_connectivity_false_on_failure(
    _mock_version, mock_client_failure, mock_server_config, mock_profile
):
    """When the OData query fails, connectivity is False and versions are all None."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_failure, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None

    env = result["environment"]
    assert env["connectivity"] is False
    assert env["versions"]["application"] is None
    assert env["versions"]["platform"] is None
    assert env["versions"]["build"] is None


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="2.0.0")
async def test_server_config_version_present(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """server_version is a non-empty string."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_success, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None
    assert isinstance(result["server_version"], str)
    assert len(result["server_version"]) > 0
    assert result["server_version"] == "2.0.0"


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_env_vars_never_exposed(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """The serialised response must not contain any actual env var values."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_success, mock_server_config, provider, mock_profile
    )
    serialised = json.dumps(response.model_dump(), default=str)

    # The profile has real-looking values — make sure none leak
    assert "test-client-secret" not in serialised
    assert "test-tenant-id" not in serialised
    assert "test-client-id" not in serialised

    # Check that no env var values appear in available_sources
    result = response.result
    assert result is not None
    for source_info in result["licence_source"]["available_sources"].values():
        # Only status, description, etc. — no actual values
        assert "status" in source_info
        for key, _value in source_info.items():
            if key == "required_params":
                # These are param *names*, not values — that's fine
                continue


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_file_source_shows_expected_columns(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """File source entry has expected_columns and accepted_tiers."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_success, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None

    file_source = result["licence_source"]["available_sources"]["file"]
    assert "expected_columns" in file_source
    assert file_source["expected_columns"] == ["user_id", "assigned_tier"]
    assert "accepted_tiers" in file_source
    assert "Enterprise" in file_source["accepted_tiers"]
    assert "Activity" in file_source["accepted_tiers"]


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_available_sources_check_env_presence(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """Test that env var presence checking works — setting vars changes status."""
    provider = AssessOnlyProvider()

    # First call: without LICENCE_FILE_PATH set — should be not_configured
    with patch.dict("os.environ", {}, clear=False):
        # Ensure the var is NOT set
        env_copy = dict(__import__("os").environ)
        env_copy.pop("LICENCE_FILE_PATH", None)
        with patch.dict("os.environ", env_copy, clear=True):
            response = await get_security_server_config(
                mock_client_success, mock_server_config, provider, mock_profile
            )
            result = response.result
            assert result is not None
            file_status = result["licence_source"]["available_sources"]["file"]["status"]
            assert file_status == "not_configured"

    # Second call: with LICENCE_FILE_PATH set — should be configured
    with patch.dict("os.environ", {"LICENCE_FILE_PATH": "/some/path.csv"}, clear=False):
        response = await get_security_server_config(
            mock_client_success, mock_server_config, provider, mock_profile
        )
        result = response.result
        assert result is not None
        file_status = result["licence_source"]["available_sources"]["file"]["status"]
        assert file_status == "configured"

    # Third call: graph with partial config (only tenant set)
    with patch.dict(
        "os.environ",
        {"D365FO_TENANT_ID": "t", "D365FO_CLIENT_ID": "", "D365FO_CLIENT_SECRET": ""},
        clear=True,
    ):
        response = await get_security_server_config(
            mock_client_success, mock_server_config, provider, mock_profile
        )
        result = response.result
        assert result is not None
        graph_status = result["licence_source"]["available_sources"]["graph"]["status"]
        assert graph_status == "partially_configured"


# ---------------------------------------------------------------------------
# Version detection via OData actions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_d365fo_version_env_var_override(
    _mock_version,
    mock_client_success,
    mock_profile,
):
    """Env var override replaces application version from OData action."""
    config = ServerConfig(D365FO_VERSION="10.0.99")
    provider = AssessOnlyProvider()
    response = await get_security_server_config(mock_client_success, config, provider, mock_profile)
    result = response.result
    assert result is not None
    versions = result["environment"]["versions"]
    # Application version overridden by env var
    assert versions["application"] == "10.0.99"
    # Platform and build still come from OData actions
    assert versions["platform"] == "7.0.7778.29"
    assert versions["build"] == "10.0.2428.63"


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_versions_from_odata_actions(
    _mock_version,
    mock_client_success,
    mock_server_config,
    mock_profile,
):
    """When no env var override, all three versions come from OData actions."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_success, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None
    versions = result["environment"]["versions"]
    assert versions["application"] == "10.0.46"
    assert versions["platform"] == "7.0.7778.29"
    assert versions["build"] == "10.0.2428.63"


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_versions_null_when_actions_fail(
    _mock_version,
    mock_server_config,
    mock_profile,
):
    """When OData actions fail, all version fields are None."""
    client = MagicMock()
    client.query = AsyncMock(return_value=[{"SecurityRoleIdentifier": "SysAdmin"}])
    client.call_action = AsyncMock(side_effect=Exception("action not found"))

    provider = AssessOnlyProvider()
    response = await get_security_server_config(client, mock_server_config, provider, mock_profile)
    result = response.result
    assert result is not None
    versions = result["environment"]["versions"]
    assert versions["application"] is None
    assert versions["platform"] is None
    assert versions["build"] is None
    # Connectivity should still be True (query succeeded)
    assert result["environment"]["connectivity"] is True


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_connectivity_false_skips_version_detection(
    _mock_version,
    mock_client_failure,
    mock_server_config,
    mock_profile,
):
    """When connectivity fails, version actions are not attempted."""
    provider = AssessOnlyProvider()
    response = await get_security_server_config(
        mock_client_failure, mock_server_config, provider, mock_profile
    )
    result = response.result
    assert result is not None
    assert result["environment"]["connectivity"] is False
    versions = result["environment"]["versions"]
    assert versions["application"] is None
    assert versions["platform"] is None
    assert versions["build"] is None
    # call_action should not have been called since connectivity failed
    mock_client_failure.call_action.assert_not_called()


@pytest.mark.asyncio
async def test_detect_versions_returns_all_three():
    """_detect_versions calls three OData actions and returns structured dict."""
    client = MagicMock()
    client.call_action = _make_call_action_mock()

    result = await _detect_versions(client)
    assert result["application"] == "10.0.46"
    assert result["platform"] == "7.0.7778.29"
    assert result["build"] == "10.0.2428.63"


@pytest.mark.asyncio
async def test_detect_versions_partial_failure():
    """_detect_versions returns None for actions that fail individually."""

    async def _partial_action(action_name: str, entity_set: str = "DataManagementEntities") -> str:
        if action_name == "GetApplicationVersion":
            return "10.0.46"
        raise RuntimeError("not supported")

    client = MagicMock()
    client.call_action = AsyncMock(side_effect=_partial_action)

    result = await _detect_versions(client)
    assert result["application"] == "10.0.46"
    assert result["platform"] is None
    assert result["build"] is None


# ---------------------------------------------------------------------------
# validate_licence_source — T025
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_licence_source_assess_only_returns_not_configured(
    mock_server_config,
):
    """AssessOnlyProvider returns not_configured with guidance."""
    provider = AssessOnlyProvider()
    response = await validate_licence_source(provider, mock_server_config)
    result = response.result
    assert result is not None
    assert result["status"] == "not_configured"
    assert result["source"] == "assess-only"
    assert "get_security_server_config" in result["error"]


@pytest.mark.asyncio
async def test_validate_licence_source_success_returns_structured_response(
    tmp_path,
    mock_server_config,
):
    """FileProvider returns connected status with validation data."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\nuser2,Enterprise\n",
        encoding="utf-8",
    )
    provider = FileProvider(str(csv_file))
    response = await validate_licence_source(provider, mock_server_config)
    result = response.result
    assert result is not None
    assert result["source"] == "file"
    assert result["status"] == "connected"
    assert result["validation"]["rows_parsed"] == 2
    assert result["validation"]["file_exists"] is True
    assert response.metadata.provider == "file"


@pytest.mark.asyncio
async def test_validate_licence_source_source_param_overrides_configured(
    tmp_path,
    mock_server_config,
):
    """source parameter creates a temporary provider different from the configured one."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\n",
        encoding="utf-8",
    )
    # Current provider is assess-only, but we override to validate file
    provider = AssessOnlyProvider()
    with patch.dict(
        "os.environ",
        {"LICENCE_FILE_PATH": str(csv_file)},
        clear=False,
    ):
        response = await validate_licence_source(
            provider,
            mock_server_config,
            source="file",
        )
    result = response.result
    assert result is not None
    assert result["source"] == "file"
    assert result["status"] == "connected"


@pytest.mark.asyncio
async def test_validate_licence_source_error_propagation(
    mock_server_config,
):
    """Errors from provider.validate() are propagated in the response."""
    provider = MagicMock()
    provider.provider_name.return_value = "file"

    # Make it a BaseLicenceSourceProvider so the isinstance check passes
    from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider

    provider.__class__ = type("MockFileProvider", (BaseLicenceSourceProvider,), {})
    provider.validate = AsyncMock(
        return_value={
            "source": "file",
            "status": "error",
            "validation": {
                "file_exists": False,
                "file_readable": False,
            },
        }
    )

    response = await validate_licence_source(provider, mock_server_config)
    result = response.result
    assert result is not None
    assert result["status"] == "error"
    assert result["validation"]["file_exists"] is False


# ---------------------------------------------------------------------------
# US8 — Licence Source Activation (T055, T056)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_graph_active_shows_active_status(
    _mock_version, mock_client_success, mock_server_config, mock_profile, graph_provider
):
    """When graph is the active provider and env vars are present, status is 'active'."""
    with patch.dict(
        "os.environ",
        {
            "D365FO_TENANT_ID": "t",
            "D365FO_CLIENT_ID": "c",
            "D365FO_CLIENT_SECRET": "s",
        },
        clear=False,
    ):
        response = await get_security_server_config(
            mock_client_success, mock_server_config, graph_provider, mock_profile
        )
    result = response.result
    assert result is not None
    graph_source = result["licence_source"]["available_sources"]["graph"]
    assert graph_source["status"] == "active"


@pytest.mark.asyncio
@patch("d365fo_security_mcp.tools.licence_source.importlib.metadata.version", return_value="1.0.0")
async def test_server_config_graph_credentials_present_but_assess_only_shows_configured(
    _mock_version, mock_client_success, mock_server_config, mock_profile
):
    """When graph credentials are present but assess-only is active, graph shows 'configured'."""
    provider = AssessOnlyProvider()
    with patch.dict(
        "os.environ",
        {
            "D365FO_TENANT_ID": "t",
            "D365FO_CLIENT_ID": "c",
            "D365FO_CLIENT_SECRET": "s",
        },
        clear=True,
    ):
        response = await get_security_server_config(
            mock_client_success, mock_server_config, provider, mock_profile
        )
    result = response.result
    assert result is not None
    graph_source = result["licence_source"]["available_sources"]["graph"]
    assert graph_source["status"] == "configured"

    # Limitations should include activation guidance for graph
    limitation_texts = " ".join(result["limitations"])
    assert "LICENCE_SOURCE=graph" in limitation_texts
    assert "credentials detected" in limitation_texts.lower()


@pytest.mark.asyncio
async def test_validate_licence_source_non_active_success_includes_activation_hint(
    tmp_path,
    mock_server_config,
):
    """Successful validation of a non-active source includes activation_hint."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\n",
        encoding="utf-8",
    )
    # Current provider is assess-only; validate file source
    provider = AssessOnlyProvider()
    with patch.dict(
        "os.environ",
        {"LICENCE_FILE_PATH": str(csv_file)},
        clear=False,
    ):
        response = await validate_licence_source(
            provider,
            mock_server_config,
            source="file",
        )
    result = response.result
    assert result is not None
    assert result["status"] == "connected"
    assert "activation_hint" in result
    assert "LICENCE_SOURCE=file" in result["activation_hint"]


@pytest.mark.asyncio
async def test_validate_licence_source_active_source_no_activation_hint(
    tmp_path,
    mock_server_config,
):
    """Validating the already-active source does not include activation_hint."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\n",
        encoding="utf-8",
    )
    # Current provider IS file — validate same source
    provider = FileProvider(str(csv_file))
    response = await validate_licence_source(provider, mock_server_config)
    result = response.result
    assert result is not None
    assert result["status"] == "connected"
    assert "activation_hint" not in result


@pytest.mark.asyncio
async def test_validate_licence_source_failed_validation_no_activation_hint(
    mock_server_config,
):
    """Failed validation does not include activation_hint."""
    provider = MagicMock()
    provider.provider_name.return_value = "file"

    from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider

    provider.__class__ = type("MockFileProvider", (BaseLicenceSourceProvider,), {})
    provider.validate = AsyncMock(
        return_value={
            "source": "file",
            "status": "error",
            "validation": {"file_exists": False},
        }
    )

    # Test the direct case: provider IS the effective provider
    response2 = await validate_licence_source(provider, mock_server_config)
    result = response2.result
    assert result is not None
    assert result["status"] == "error"
    assert "activation_hint" not in result


def test_create_provider_graph_with_credentials():
    """create_provider('graph', ...) constructs GraphProvider with credentials."""
    from d365fo_security_mcp.tools.providers import create_provider
    from d365fo_security_mcp.tools.providers.graph_provider import GraphProvider

    provider = create_provider(
        "graph",
        tenant_id="t-id",
        client_id="c-id",
        client_secret="c-secret",
        graph_scope="https://graph.microsoft.com/.default",
    )
    assert isinstance(provider, GraphProvider)
    assert provider.provider_name() == "graph"
    assert provider._tenant_id == "t-id"
    assert provider._client_id == "c-id"
    assert provider._client_secret == "c-secret"
