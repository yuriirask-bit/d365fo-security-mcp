from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.over_licensed import _build_stale_warning
from d365fo_security_mcp.tools.providers.base import LicenceSourceProvider

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def detect_under_licensed(
    client: ODataClient,
    tier_config: LicenceTierConfig,
    provider: LicenceSourceProvider,
    *,
    redact_pii: bool = False,
    batch_size: int = 50,
    stale_threshold_days: int = 7,
) -> ToolResponse:
    """Detect users whose assigned licence tier is lower than what their
    security roles require — a compliance risk under Microsoft enforcement.
    """
    start = time.monotonic()
    warnings: list[str] = []

    # Assess-only mode cannot determine under-licensing
    if provider.provider_name() == "assess-only":
        return ToolResponse(
            result=None,
            metadata=ResponseMetadata(
                duration_ms=int((time.monotonic() - start) * 1000),
                environment=getattr(client, "environment", ""),
            ),
            warnings=[
                "Under-licensed detection requires an external licence source. "
                "Configure licence_source as 'graph', 'ppac', or 'file'."
            ],
        )

    # Get assessments
    assessment_response = await assess_all_users(
        client, tier_config, redact_pii=redact_pii, batch_size=batch_size
    )
    assessments: list[dict[str, Any]] = assessment_response.result.get("assessments", [])

    # Get assigned licences from provider
    assigned_licences: dict[str, str] = await provider.get_assigned_licences()

    # Build lookup maps
    tier_priority: dict[str, int] = tier_config._priority
    tier_display: dict[str, str] = {t.name: t.display_name for t in tier_config.tiers}

    under_licensed_users: list[dict[str, Any]] = []

    for assessment in assessments:
        user_id: str = assessment.get("user_id", "")
        user_name: str = assessment.get("user_name", user_id)
        user_email: str = assessment.get("user_email", "")
        required_tier_data = assessment.get("required_tier")
        required_tier_key: str = (
            required_tier_data.get("name", "") if isinstance(required_tier_data, dict) else ""
        )

        if not required_tier_key:
            continue

        # Try matching by user_id, then email (all lowercased by provider)
        matched_tier: str | None = (
            assigned_licences.get(user_id.lower())
            or assigned_licences.get(user_email.lower() if user_email else "")
            or None
        )
        if matched_tier is None:
            safe_uid = _redact(user_id, redact_pii)
            warnings.append(f"User '{safe_uid}': licence status unknown — cannot assess compliance")
            continue

        assigned_tier_key: str = matched_tier
        assigned_priority = tier_priority.get(assigned_tier_key, 0)
        required_priority = tier_priority.get(required_tier_key, 0)

        if assigned_priority < required_priority:
            assigned_display = tier_display.get(assigned_tier_key, assigned_tier_key)
            required_display = tier_display.get(required_tier_key, required_tier_key)

            under_licensed_users.append(
                {
                    "user_id": user_id,
                    "user_name": user_name,
                    "assigned_tier": assigned_display,
                    "required_tier": required_display,
                    "tier_gap": f"{assigned_display} \u2192 {required_display}",
                    "enforcement_risk": "User may be blocked by Microsoft enforcement",
                }
            )

    # Build stale data warning
    warning: str | None = _build_stale_warning(provider, stale_threshold_days)

    return ToolResponse(
        result={
            "warning": warning,
            "under_licensed_count": len(under_licensed_users),
            "users": under_licensed_users,
        },
        metadata=ResponseMetadata(
            duration_ms=int((time.monotonic() - start) * 1000),
            provider=provider.provider_name(),
            environment=getattr(client, "environment", ""),
        ),
        warnings=warnings,
    )
