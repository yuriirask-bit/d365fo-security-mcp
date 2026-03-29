from __future__ import annotations

from typing import Any

from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider


class PpacProvider(BaseLicenceSourceProvider):
    async def get_assigned_licences(self) -> dict[str, str]:
        raise NotImplementedError(
            "Power Platform Admin Center provider not yet implemented. "
            "Configure licence_source='file' or 'assess-only' as an alternative."
        )

    def provider_name(self) -> str:
        return "ppac"

    async def validate(self) -> dict[str, Any]:
        return {
            "status": "error",
            "validation": None,
            "error": "PPAC provider is not yet implemented",
        }
