"""Unit tests for centralised service account filter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.sod.filters import (
    filter_non_native_users,
    get_native_provider,
    is_native_user,
)


def _make_client(
    *,
    admin_provider: str = "https://sts.windows.net/abc/",
    admin_exists: bool = True,
) -> MagicMock:
    client = MagicMock()
    client.environment = "test.operations.dynamics.com"

    async def _query(entity: str, **kwargs):
        if entity == "SystemUsers":
            if not admin_exists:
                return []
            return [{"UserID": "Admin", "NetworkDomain": admin_provider}]
        return []

    client.query = AsyncMock(side_effect=_query)
    return client


@pytest.mark.asyncio
async def test_get_native_provider_returns_admin_provider():
    client = _make_client(admin_provider="https://sts.windows.net/abc/")
    provider, warnings = await get_native_provider(client)

    assert provider == "https://sts.windows.net/abc/"
    assert warnings == []


@pytest.mark.asyncio
async def test_get_native_provider_admin_not_found():
    client = _make_client(admin_exists=False)
    provider, warnings = await get_native_provider(client)

    assert provider == ""
    assert any("not found" in w for w in warnings)


@pytest.mark.asyncio
async def test_get_native_provider_admin_no_provider_field():
    client = _make_client(admin_provider="")
    provider, warnings = await get_native_provider(client)

    assert provider == ""
    assert any("no NetworkDomain" in w for w in warnings)


def test_is_native_user_same_provider():
    user = {"UserID": "jsmith", "NetworkDomain": "https://sts.windows.net/abc/"}
    assert is_native_user(user, "https://sts.windows.net/abc/") is True


def test_is_native_user_different_provider():
    user = {"UserID": "RetailServiceAccount", "NetworkDomain": "https://other/"}
    assert is_native_user(user, "https://sts.windows.net/abc/") is False


def test_is_native_user_no_baseline_treats_all_as_native():
    user = {"UserID": "anyone", "NetworkDomain": "https://other/"}
    assert is_native_user(user, "") is True


def test_filter_non_native_users_excludes_different_provider():
    users = [
        {"UserID": "jsmith", "NetworkDomain": "https://sts.windows.net/abc/"},
        {"UserID": "RetailServiceAccount", "NetworkDomain": "https://other/"},
        {"UserID": "aclerk", "NetworkDomain": "https://sts.windows.net/abc/"},
    ]
    filtered, excluded = filter_non_native_users(users, "https://sts.windows.net/abc/")

    assert len(filtered) == 2
    assert excluded == 1
    assert all(u["UserID"] != "RetailServiceAccount" for u in filtered)


def test_filter_non_native_users_no_baseline_skips_filtering():
    users = [
        {"UserID": "jsmith", "NetworkDomain": "https://sts.windows.net/abc/"},
        {"UserID": "ServiceAccount", "NetworkDomain": "https://other/"},
    ]
    filtered, excluded = filter_non_native_users(users, "")

    assert len(filtered) == 2
    assert excluded == 0


def test_filter_non_native_users_empty_list():
    filtered, excluded = filter_non_native_users([], "https://sts.windows.net/abc/")

    assert filtered == []
    assert excluded == 0


def test_filter_non_native_users_all_same_provider():
    users = [
        {"UserID": "jsmith", "NetworkDomain": "https://sts.windows.net/abc/"},
        {"UserID": "aclerk", "NetworkDomain": "https://sts.windows.net/abc/"},
    ]
    filtered, excluded = filter_non_native_users(users, "https://sts.windows.net/abc/")

    assert len(filtered) == 2
    assert excluded == 0
