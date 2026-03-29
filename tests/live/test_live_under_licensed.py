"""Live tests for detect_under_licensed_users — requires --live flag."""

from __future__ import annotations

import pytest

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider
from d365fo_security_mcp.tools.under_licensed import detect_under_licensed


@pytest.mark.live
class TestLiveUnderLicensed:
    """Under-licensed detection in assess-only mode against a real D365 environment.

    Under-licensed detection requires an external licence source. In assess-only
    mode the tool must return a None result with a warning — this is the only
    scenario testable without Graph/PPAC/file credentials.
    """

    async def test_live_under_licensed_assess_only_returns_none_result(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Assess-only mode must return result=None (cannot detect without licence source)."""
        response = await detect_under_licensed(live_client, live_tier_config, live_provider)

        assert response.result is None

    async def test_live_under_licensed_assess_only_has_warning(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Assess-only mode must explain the limitation in the warnings array."""
        response = await detect_under_licensed(live_client, live_tier_config, live_provider)

        assert len(response.warnings) > 0
        combined = " ".join(response.warnings).lower()
        assert any(
            keyword in combined
            for keyword in ("assess-only", "licence source", "external", "cannot")
        )

    async def test_live_under_licensed_envelope_shape_valid(
        self,
        live_client: ODataClient,
        live_tier_config: LicenceTierConfig,
        live_provider: AssessOnlyProvider,
    ) -> None:
        """Even in assess-only mode the ToolResponse envelope must be well-formed."""
        response = await detect_under_licensed(live_client, live_tier_config, live_provider)

        assert response.metadata.environment != ""
        assert response.metadata.duration_ms >= 0
        assert isinstance(response.warnings, list)
