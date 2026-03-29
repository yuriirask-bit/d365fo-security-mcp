"""Live test fixtures — require real D365 F&O credentials in environment or .env file."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider


@pytest.fixture(scope="session")
def live_profile() -> D365Profile:
    try:
        return D365Profile()  # type: ignore[call-arg]
    except ValidationError as exc:
        missing = [e["loc"][0] for e in exc.errors() if e["type"] == "missing"]
        missing_str = ", ".join(str(m) for m in missing)
        pytest.skip(f"D365FO credentials missing in environment/.env: {missing_str}")


@pytest.fixture
def live_client(live_profile: D365Profile) -> ODataClient:
    return ODataClient(live_profile)


@pytest.fixture(scope="session")
def live_tier_config() -> LicenceTierConfig:
    config = ServerConfig()  # type: ignore[call-arg]
    return LicenceTierConfig(currency=config.currency)


@pytest.fixture(scope="session")
def live_server_config() -> ServerConfig:
    """Load server config from environment/.env for live tests."""
    return ServerConfig()  # type: ignore[call-arg]


@pytest.fixture(scope="session")
def live_provider() -> AssessOnlyProvider:
    """Default assess-only provider for live tests (no external licence source needed)."""
    return AssessOnlyProvider()
