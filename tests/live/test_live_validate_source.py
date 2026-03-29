"""Live tests for validate_licence_source — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.config import ServerConfig
from d365fo_security_mcp.tools.licence_source import validate_licence_source
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider


@pytest.mark.live
class TestLiveValidateLicenceSource:
    """Licence source validation against a real environment."""

    async def test_live_validate_assess_only_returns_not_configured(
        self,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Assess-only provider should return not_configured status."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await validate_licence_source(live_provider, config)

        result = response.result
        assert result["source"] == "assess-only"
        assert result["status"] == "not_configured"
        assert result["error"] is not None
        assert "get_security_server_config" in result["error"]

    async def test_live_validate_assess_only_has_valid_envelope(
        self,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Response must have source, status, and validation fields."""
        config = ServerConfig()  # type: ignore[call-arg]
        response = await validate_licence_source(live_provider, config)

        result = response.result
        assert "source" in result
        assert "status" in result
