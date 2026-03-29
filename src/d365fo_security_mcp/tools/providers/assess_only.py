from __future__ import annotations

from typing import Any

from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider


class AssessOnlyProvider(BaseLicenceSourceProvider):
    async def get_assigned_licences(self) -> dict[str, str]:
        return {}

    def provider_name(self) -> str:
        return "assess-only"

    async def validate(self) -> dict[str, Any]:
        return {
            "status": "not_configured",
            "validation": None,
            "error": (
                "No external licence source configured. "
                "Call get_security_server_config for available options and setup guidance."
            ),
        }
