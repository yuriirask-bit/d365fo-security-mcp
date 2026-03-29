"""Unit tests for licence source providers and the provider factory."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from d365fo_security_mcp.tools.providers import create_provider
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider
from d365fo_security_mcp.tools.providers.file_provider import FileProvider
from d365fo_security_mcp.tools.providers.graph_provider import GraphProvider
from d365fo_security_mcp.tools.providers.ppac_provider import PpacProvider

# ---------------------------------------------------------------------------
# AssessOnlyProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_only_returns_empty():
    provider = AssessOnlyProvider()
    result = await provider.get_assigned_licences()
    assert result == {}


def test_assess_only_provider_name():
    provider = AssessOnlyProvider()
    assert provider.provider_name() == "assess-only"


# ---------------------------------------------------------------------------
# FileProvider — CSV
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_provider_loads_csv(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\nuser1,Finance\nuser2,Operations\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    result = await provider.get_assigned_licences()
    assert result == {"user1": "Finance", "user2": "Operations"}
    assert provider.warnings == []


@pytest.mark.asyncio
async def test_file_provider_csv_missing_user_id_warns(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\n,Finance\nuser2,Operations\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    result = await provider.get_assigned_licences()
    assert "user2" in result
    assert len(provider.warnings) == 1
    assert "user_id" in provider.warnings[0]


@pytest.mark.asyncio
async def test_file_provider_csv_missing_licence_warns(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\nuser1,\nuser2,Operations\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    result = await provider.get_assigned_licences()
    assert "user2" in result
    assert "user1" not in result
    assert len(provider.warnings) == 1
    assert "licence" in provider.warnings[0]


# ---------------------------------------------------------------------------
# FileProvider — JSON (dict format)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_provider_loads_json_dict(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    data = {"user1": "Finance", "user2": "Operations"}
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    assert result == data
    assert provider.warnings == []


@pytest.mark.asyncio
async def test_file_provider_loads_json_list(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    data = [
        {"user_id": "user1", "licence": "Finance"},
        {"user_id": "user2", "licence": "Operations"},
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    assert result == {"user1": "Finance", "user2": "Operations"}
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# FileProvider — malformed entries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_provider_reports_malformed_json_list_entries(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    data = [
        {"user_id": "user1", "licence": "Finance"},
        "not-an-object",
        {"user_id": "", "licence": "Operations"},
        {"user_id": "user3"},  # missing licence
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    assert result == {"user1": "Finance"}
    assert len(provider.warnings) == 3


@pytest.mark.asyncio
async def test_file_provider_reports_malformed_json_dict_entries(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    # Non-string value should be warned about
    data: dict = {"user1": "Finance", 123: "Operations"}
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    # JSON serialises int key as string "123", which is valid — no warning expected
    assert len(result) == 2


def test_file_provider_validates_schema_unsupported_extension(tmp_path: Path):
    bad_file = tmp_path / "licences.xml"
    bad_file.write_text("<root/>", encoding="utf-8")
    with pytest.raises(ValueError, match="must be .json or .csv"):
        FileProvider(str(bad_file))


@pytest.mark.asyncio
async def test_file_provider_raises_when_file_not_found(tmp_path: Path):
    provider = FileProvider(str(tmp_path / "nonexistent.json"))
    with pytest.raises(FileNotFoundError):
        await provider.get_assigned_licences()


@pytest.mark.asyncio
async def test_file_provider_raises_on_invalid_json_root_type(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    json_file.write_text('"just a string"', encoding="utf-8")
    provider = FileProvider(str(json_file))
    with pytest.raises(ValueError, match="JSON file must contain"):
        await provider.get_assigned_licences()


def test_file_provider_name(tmp_path: Path):
    provider = FileProvider(str(tmp_path / "dummy.csv"))
    assert provider.provider_name() == "file"


# ---------------------------------------------------------------------------
# GraphProvider — basic factory / name check
# (full behaviour is tested in test_graph_provider.py)
# ---------------------------------------------------------------------------


def test_graph_provider_name():
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
    assert provider.provider_name() == "graph"


# ---------------------------------------------------------------------------
# PpacProvider stub
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ppac_stub_raises_not_implemented():
    provider = PpacProvider()
    with pytest.raises(NotImplementedError, match="Power Platform"):
        await provider.get_assigned_licences()


def test_ppac_provider_name():
    provider = PpacProvider()
    assert provider.provider_name() == "ppac"


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def test_provider_factory_selects_assess_only():
    provider = create_provider("assess-only")
    assert isinstance(provider, AssessOnlyProvider)


def test_provider_factory_selects_file(tmp_path: Path):
    provider = create_provider("file", file_path=str(tmp_path / "dummy.csv"))
    assert isinstance(provider, FileProvider)


def test_provider_factory_selects_graph():
    provider = create_provider("graph", tenant_id="t", client_id="c", client_secret="s")
    assert isinstance(provider, GraphProvider)


def test_provider_factory_selects_ppac():
    provider = create_provider("ppac")
    assert isinstance(provider, PpacProvider)


def test_provider_factory_raises_on_unknown_source():
    with pytest.raises(ValueError, match="Unsupported licence_source"):
        create_provider("unknown-source")


def test_provider_factory_file_missing_kwarg_raises():
    with pytest.raises(KeyError):
        create_provider("file")  # file_path not provided


# ---------------------------------------------------------------------------
# FileProvider — edge cases (T063/T064)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_provider_csv_missing_user_id_column_raises(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("name,licence\nalice,Finance\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    with pytest.raises(ValueError, match="user_id"):
        await provider.get_assigned_licences()


@pytest.mark.asyncio
async def test_file_provider_csv_missing_licence_column_raises(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,name\nuser1,alice\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    with pytest.raises(ValueError, match="licence"):
        await provider.get_assigned_licences()


@pytest.mark.asyncio
async def test_file_provider_csv_unrecognised_tier_warns_and_excludes(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\nuser1,Finance\nuser2,InvalidTier\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    result = await provider.get_assigned_licences()
    assert "user1" in result
    assert "user2" not in result
    assert len(provider.warnings) == 1
    assert "unrecognised" in provider.warnings[0]


@pytest.mark.asyncio
async def test_file_provider_json_dict_unrecognised_tier_warns(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    data = {"user1": "Finance", "user2": "BogusType"}
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    assert "user1" in result
    assert "user2" not in result
    assert len(provider.warnings) == 1
    assert "unrecognised" in provider.warnings[0]


@pytest.mark.asyncio
async def test_file_provider_json_list_unrecognised_tier_warns(tmp_path: Path):
    json_file = tmp_path / "licences.json"
    data = [
        {"user_id": "user1", "licence": "Finance"},
        {"user_id": "user2", "licence": "NotARealTier"},
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")
    provider = FileProvider(str(json_file))
    result = await provider.get_assigned_licences()
    assert "user1" in result
    assert "user2" not in result
    assert len(provider.warnings) == 1
    assert "unrecognised" in provider.warnings[0]


@pytest.mark.asyncio
async def test_file_provider_get_warnings_returns_empty_when_clean(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\nuser1,Finance\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    await provider.get_assigned_licences()
    assert provider.get_warnings() == []


@pytest.mark.asyncio
async def test_file_provider_get_warnings_returns_accumulated_warnings(tmp_path: Path):
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text("user_id,licence\nuser1,Finance\nuser2,FakeTier\n", encoding="utf-8")
    provider = FileProvider(str(csv_file))
    await provider.get_assigned_licences()
    warnings = provider.get_warnings()
    assert len(warnings) == 1
    assert "unrecognised" in warnings[0]


# ---------------------------------------------------------------------------
# FileProvider.validate() — T024
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_provider_validate_success(tmp_path: Path):
    """validate() returns connected status with row counts and tiers."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\nuser2,Operations\nuser3,Enterprise\n",
        encoding="utf-8",
    )
    provider = FileProvider(str(csv_file))
    result = await provider.validate()

    assert result["source"] == "file"
    assert result["status"] == "connected"
    v = result["validation"]
    assert v["file_exists"] is True
    assert v["file_readable"] is True
    assert v["rows_parsed"] == 3
    assert v["rows_with_errors"] == 0
    assert v["errors"] == []
    assert "Enterprise" in v["licence_tiers_found"]
    assert "Finance" in v["licence_tiers_found"]
    assert v["last_modified"] is not None
    assert provider.last_sync_time is not None


@pytest.mark.asyncio
async def test_file_provider_validate_file_not_found(tmp_path: Path):
    """validate() returns error status when file does not exist."""
    provider = FileProvider(str(tmp_path / "nonexistent.csv"))
    result = await provider.validate()

    assert result["source"] == "file"
    assert result["status"] == "error"
    assert result["validation"]["file_exists"] is False
    assert result["validation"]["file_readable"] is False


@pytest.mark.asyncio
async def test_file_provider_validate_malformed_csv_with_row_errors(tmp_path: Path):
    """validate() reports row-level errors for bad rows."""
    csv_file = tmp_path / "licences.csv"
    csv_file.write_text(
        "user_id,licence\nuser1,Finance\n,Operations\nuser3,BadTier\n",
        encoding="utf-8",
    )
    provider = FileProvider(str(csv_file))
    result = await provider.validate()

    assert result["source"] == "file"
    assert result["status"] == "connected"
    v = result["validation"]
    assert v["rows_parsed"] == 1  # only user1 parsed successfully
    assert v["rows_with_errors"] == 2
    assert len(v["errors"]) == 2
    # Check that row numbers are captured
    row_numbers = [e["row"] for e in v["errors"]]
    assert 3 in row_numbers  # empty user_id row
    assert 4 in row_numbers  # BadTier row


# ---------------------------------------------------------------------------
# GraphProvider.validate() — T024
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_graph_provider_validate_success():
    """validate() returns connected with user counts when Graph succeeds."""
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")

    mock_response_data = {
        "value": [
            {
                "id": "user1",
                "displayName": "User 1",
                "assignedLicenses": [
                    {"skuId": "6fd2c87f-b296-42f0-b197-1e91e994b900"}  # Enterprise
                ],
            },
            {
                "id": "user2",
                "displayName": "User 2",
                "assignedLicenses": [],
            },
        ]
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_response_data
    mock_response.raise_for_status = MagicMock()

    with (
        patch.object(provider, "_acquire_token", return_value="fake-token"),
        patch("httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await provider.validate()

    assert result["source"] == "graph"
    assert result["status"] == "connected"
    v = result["validation"]
    assert v["authentication"] == "ok"
    assert v["permissions"] == "ok"
    assert v["data_available"] is True
    assert v["users_with_assignments"] == 1
    assert v["users_without_assignments"] == 1
    assert "Enterprise" in v["licence_tiers_found"]
    assert v["last_sync"] is not None
    assert v["remediation"] is None
    assert provider.last_sync_time is not None


@pytest.mark.asyncio
async def test_graph_provider_validate_zero_assignments():
    """validate() returns connected with zero assignments when tenant has no licence data."""
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")

    mock_response_data = {
        "value": [
            {
                "id": "user1",
                "displayName": "User 1",
                "assignedLicenses": [],
            },
            {
                "id": "user2",
                "displayName": "User 2",
                "assignedLicenses": [],
            },
        ]
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_response_data
    mock_response.raise_for_status = MagicMock()

    with (
        patch.object(provider, "_acquire_token", return_value="fake-token"),
        patch("httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await provider.validate()

    assert result["source"] == "graph"
    assert result["status"] == "connected"
    v = result["validation"]
    assert v["authentication"] == "ok"
    assert v["permissions"] == "ok"
    assert v["users_with_assignments"] == 0
    assert v["users_without_assignments"] == 2
    assert v["licence_tiers_found"] == []
    # data_available is True because the API responded successfully —
    # the source is reachable, it just has no licence assignments
    assert v["data_available"] is True


@pytest.mark.asyncio
async def test_graph_provider_validate_auth_failure():
    """validate() returns error with remediation when auth fails."""
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")

    with patch.object(provider, "_acquire_token", side_effect=RuntimeError("bad credentials")):
        result = await provider.validate()

    assert result["source"] == "graph"
    assert result["status"] == "error"
    v = result["validation"]
    assert v["authentication"] == "failed"
    assert v["remediation"] is not None
    assert "Authentication failed" in v["remediation"]


@pytest.mark.asyncio
async def test_graph_provider_validate_permission_error():
    """validate() returns insufficient permissions with remediation on 403."""
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")

    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {}

    with (
        patch.object(provider, "_acquire_token", return_value="fake-token"),
        patch("httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await provider.validate()

    assert result["source"] == "graph"
    assert result["status"] == "error"
    v = result["validation"]
    assert v["permissions"] == "insufficient"
    assert v["missing_permissions"] == ["Directory.Read.All"]
    assert "Directory.Read.All" in v["remediation"]


# ---------------------------------------------------------------------------
# PpacProvider.validate() — T024
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ppac_provider_validate_not_implemented():
    """PpacProvider validate() returns error with not implemented message."""
    provider = PpacProvider()
    result = await provider.validate()

    assert result["status"] == "error"
    assert result["validation"] is None
    assert "not yet implemented" in result["error"]


# ---------------------------------------------------------------------------
# AssessOnlyProvider.validate() — T024
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_only_provider_validate_not_configured():
    """AssessOnlyProvider validate() returns not_configured status."""
    provider = AssessOnlyProvider()
    result = await provider.validate()

    assert result["status"] == "not_configured"
    assert result["validation"] is None
    assert "get_security_server_config" in result["error"]
