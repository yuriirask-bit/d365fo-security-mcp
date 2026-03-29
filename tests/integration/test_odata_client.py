from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from d365fo_security_mcp.models.config import D365Profile
from d365fo_security_mcp.odata.client import ODataClient, ThrottlingError

BASE_URL = "https://test.operations.dynamics.com"
DATA_URL = f"{BASE_URL}/data"


@pytest.fixture
def profile() -> D365Profile:
    return D365Profile(
        base_url=BASE_URL,
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        request_delay_ms=0,
        max_retries=2,
    )


def _make_client(profile: D365Profile, handler) -> ODataClient:
    """Create an ODataClient with an injected mock transport and fake token."""
    client = ODataClient(profile, transport=httpx.MockTransport(handler))
    mock_token = MagicMock()
    mock_token.get_access_token.return_value = "fake-token"
    client._token_manager = mock_token
    return client


async def test_odata_client_query_returns_records(profile: D365Profile) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [{"id": 1}, {"id": 2}]})

    client = _make_client(profile, handler)
    try:
        records = await client.query("Entity")
    finally:
        await client.close()

    assert len(records) == 2
    assert records[0] == {"id": 1}
    assert records[1] == {"id": 2}


async def test_odata_client_pagination_transparent(profile: D365Profile) -> None:
    next_link = f"{DATA_URL}/Entity?skiptoken=1"
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if "skiptoken" not in str(request.url):
            return httpx.Response(
                200,
                json={"value": [{"id": 1}], "@odata.nextLink": next_link},
            )
        return httpx.Response(200, json={"value": [{"id": 2}]})

    client = _make_client(profile, handler)
    try:
        records = await client.query("Entity")
    finally:
        await client.close()

    assert len(records) == 2
    assert records[0] == {"id": 1}
    assert records[1] == {"id": 2}
    assert call_count == 2


async def test_odata_client_401_retry_with_fresh_token(profile: D365Profile) -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(401)
        return httpx.Response(200, json={"value": [{"id": 99}]})

    client = _make_client(profile, handler)
    try:
        records = await client.query("Entity")
    finally:
        await client.close()

    assert records == [{"id": 99}]
    assert call_count == 2


async def test_odata_client_429_retries_with_retry_after(profile: D365Profile) -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"value": [{"id": 42}]})

    client = _make_client(profile, handler)
    try:
        records = await client.query("Entity")
    finally:
        await client.close()

    assert records == [{"id": 42}]
    assert call_count == 2


async def test_odata_client_429_exhausted_raises_throttling_error(
    profile: D365Profile,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    client = _make_client(profile, handler)
    try:
        with pytest.raises(ThrottlingError):
            await client.query("Entity")
    finally:
        await client.close()


async def test_odata_client_select_and_filter_params(profile: D365Profile) -> None:
    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(200, json={"value": []})

    client = _make_client(profile, handler)
    try:
        await client.query("Entity", select=["A", "B"], filter_expr="X eq 'Y'")
    finally:
        await client.close()

    assert captured_request is not None
    params = dict(captured_request.url.params)
    assert params["$select"] == "A,B"
    assert params["$filter"] == "X eq 'Y'"
