"""Unit tests for GraphProvider using respx to mock httpx."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import respx
from httpx import Response

from d365fo_security_mcp.tools.providers.graph_provider import GraphProvider

_GRAPH_USERS_URL = (
    "https://graph.microsoft.com/v1.0/users"
    "?$select=id,displayName,userPrincipalName,mail,mailNickname,assignedLicenses"
)

# Known SKU GUIDs (must match the mapping in graph_provider.py)
SKU_FINANCE = "6fd2c87f-b296-42f0-b197-1e91e994b900"  # Enterprise
SKU_ACTIVITY = "f30db892-07e9-47e9-837c-80727f46fd3d"  # Activity
SKU_TEAM_MEMBERS = "ccba3cfe-71ef-423a-bd87-b6df3dce59a9"  # Universal
SKU_UNKNOWN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_mock_msal() -> MagicMock:
    """Return a patched msal.ConfidentialClientApplication that always succeeds."""
    mock_app = MagicMock()
    mock_app.acquire_token_for_client.return_value = {"access_token": "fake-token"}
    return mock_app


def _single_page_response(users: list[dict]) -> dict:
    return {"value": users}


def _page_with_next_link(users: list[dict], next_url: str) -> dict:
    return {"value": users, "@odata.nextLink": next_url}


def _user(
    entra_id: str,
    skus: list[str],
    *,
    display_name: str = "",
    upn: str = "",
    mail: str = "",
    nickname: str = "",
) -> dict:
    """Build a mock Graph API user object."""
    user: dict = {
        "id": entra_id,
        "displayName": display_name,
        "userPrincipalName": upn,
        "mail": mail,
        "mailNickname": nickname,
        "assignedLicenses": [{"skuId": s} for s in skus],
    }
    return user


# ---------------------------------------------------------------------------
# T062-1: Enterprise SKU resolves correctly + multi-key output
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_resolves_enterprise_sku():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [
                    _user(
                        "user-1",
                        [SKU_FINANCE],
                        display_name="Alice",
                        upn="alice@contoso.com",
                        nickname="alice",
                    )
                ]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    # Multi-key: entra id, upn, local part, nickname all resolve to Enterprise
    assert result["user-1"] == "Enterprise"
    assert result["alice@contoso.com"] == "Enterprise"
    assert result["alice"] == "Enterprise"
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# T062-2: Activity SKU resolves correctly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_resolves_activity_sku():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [_user("user-2", [SKU_ACTIVITY], display_name="Bob", upn="bob@contoso.com")]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    assert result["user-2"] == "Activity"
    assert result["bob@contoso.com"] == "Activity"
    assert result["bob"] == "Activity"
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# T062-3: Team Members (Universal) SKU resolves correctly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_resolves_team_member_sku():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [_user("user-3", [SKU_TEAM_MEMBERS], display_name="Carol", upn="carol@contoso.com")]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    assert result["user-3"] == "Universal"
    assert result["carol"] == "Universal"
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# T062-4: Pagination — two pages, all users returned
# ---------------------------------------------------------------------------

_NEXT_PAGE_URL = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc123"


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_handles_pagination():
    mock_app = _make_mock_msal()

    # First page — includes nextLink
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_page_with_next_link(
                [_user("user-1", [SKU_FINANCE], upn="alice@contoso.com")],
                _NEXT_PAGE_URL,
            ),
        )
    )
    # Second page — no nextLink
    respx.get(_NEXT_PAGE_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response([_user("user-2", [SKU_ACTIVITY], upn="bob@contoso.com")]),
        )
    )

    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    assert result["user-1"] == "Enterprise"
    assert result["alice"] == "Enterprise"
    assert result["user-2"] == "Activity"
    assert result["bob"] == "Activity"
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# T062-5: Unknown SKU is excluded from results but logged as a warning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_unknown_sku_logged_as_warning():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [_user("user-x", [SKU_UNKNOWN], display_name="Unknown User")]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    # User has no known D365 SKU — should not appear in results
    assert "user-x" not in result
    assert len(provider.warnings) == 1
    assert SKU_UNKNOWN in provider.warnings[0]


# ---------------------------------------------------------------------------
# T062-6: provider_name() returns "graph"
# ---------------------------------------------------------------------------


def test_graph_provider_name_returns_graph():
    provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
    assert provider.provider_name() == "graph"


# ---------------------------------------------------------------------------
# T062-7: User with multiple SKUs gets the highest tier (Enterprise wins)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_user_with_multiple_skus_gets_highest_tier():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [_user("user-multi", [SKU_ACTIVITY, SKU_FINANCE], upn="multi@contoso.com")]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    assert result["user-multi"] == "Enterprise"
    assert result["multi"] == "Enterprise"
    assert provider.warnings == []


# ---------------------------------------------------------------------------
# T062-8: Case-insensitive multi-key matching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_graph_provider_keys_are_lowercased():
    mock_app = _make_mock_msal()
    respx.get(_GRAPH_USERS_URL).mock(
        return_value=Response(
            200,
            json=_single_page_response(
                [
                    _user(
                        "ABC-123",
                        [SKU_FINANCE],
                        upn="Admin@Contoso.com",
                        mail="Admin@Contoso.com",
                        nickname="Admin",
                    )
                ]
            ),
        )
    )
    with patch("msal.ConfidentialClientApplication", return_value=mock_app):
        provider = GraphProvider(tenant_id="t", client_id="c", client_secret="s")
        result = await provider.get_assigned_licences()

    # All keys should be lowercased
    assert result["abc-123"] == "Enterprise"
    assert result["admin@contoso.com"] == "Enterprise"
    assert result["admin"] == "Enterprise"
    # Original casing should NOT be present
    assert "ABC-123" not in result
    assert "Admin" not in result
