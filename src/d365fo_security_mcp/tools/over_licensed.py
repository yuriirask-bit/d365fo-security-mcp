from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.providers.base import LicenceSourceProvider

logger = logging.getLogger(__name__)


def _redact(value: str, should_redact: bool) -> str:
    if not should_redact or not value:
        return value
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _build_stale_warning(
    provider: LicenceSourceProvider,
    stale_threshold_days: int,
) -> str | None:
    """Return a stale-data warning string if the provider's last sync exceeds the threshold."""
    last_sync = getattr(provider, "last_sync_time", None)
    if not isinstance(last_sync, datetime) or stale_threshold_days <= 0:
        return None
    threshold = datetime.now(timezone.utc) - timedelta(days=stale_threshold_days)
    if last_sync < threshold:
        return (
            f"Licence source data is stale (last synced: {last_sync.isoformat()}, "
            f"threshold: {stale_threshold_days} days). Results may not reflect current "
            "licence assignments. Consider refreshing the licence data."
        )
    return None


async def detect_over_licensed(
    client: ODataClient,
    tier_config: LicenceTierConfig,
    provider: LicenceSourceProvider,
    *,
    redact_pii: bool = False,
    batch_size: int = 50,
    stale_threshold_days: int = 7,
) -> ToolResponse:
    """Detect users whose assigned licence exceeds their role-based requirement."""
    started_at = time.monotonic()
    warnings: list[str] = []

    # Get assessments
    assessment_response = await assess_all_users(client, tier_config, batch_size=batch_size)
    assessments: list[dict[str, Any]] = assessment_response.result.get("assessments", [])

    is_assess_only: bool = provider.provider_name() == "assess-only"
    over_licensed_users: list[dict[str, Any]] = []
    mode = "projection" if is_assess_only else "live"

    if is_assess_only:
        # Projection mode: report users who could be on a cheaper tier
        for assessment in assessments:
            user_id: str = assessment.get("user_id", "")
            user_name: str = assessment.get("user_name", user_id)
            required_tier_data = assessment.get("required_tier")
            if not isinstance(required_tier_data, dict):
                continue

            tier_name = required_tier_data.get("name", "None")
            tier_cost = float(required_tier_data.get("monthly_cost", 0))

            # Skip users already at no-cost tiers
            if tier_cost <= 0:
                continue

            over_licensed_users.append(
                {
                    "user_id": user_id,
                    "user_name": "REDACTED" if redact_pii else user_name,
                    "assigned_tier": tier_name,
                    "required_tier": tier_name,
                    "monthly_savings": 0.0,
                    "annual_savings": 0.0,
                }
            )
    else:
        # Live mode: compare assigned vs required
        assigned_licences: dict[str, str] = await provider.get_assigned_licences()

        for assessment in assessments:
            user_id = assessment.get("user_id", "")
            user_name = assessment.get("user_name", user_id)
            user_email = assessment.get("user_email", "")
            required_tier_data = assessment.get("required_tier")
            if not isinstance(required_tier_data, dict):
                continue

            required_name = required_tier_data.get("name", "None")
            required_cost = float(required_tier_data.get("monthly_cost", 0))

            # Try matching by user_id, then email (all lowercased by provider)
            matched_tier: str | None = (
                assigned_licences.get(user_id.lower())
                or assigned_licences.get(user_email.lower() if user_email else "")
                or None
            )
            if matched_tier is None:
                safe_uid = _redact(user_id, redact_pii)
                warnings.append(
                    f"User '{safe_uid}' found in assessment but has no matching "
                    "licence in the provider data (unmatched)."
                )
                continue

            assigned_name: str = matched_tier
            assigned_tier = tier_config.get_by_name(assigned_name)
            assigned_cost = float(assigned_tier.monthly_cost)

            assigned_rank = tier_config.priority(assigned_name)
            required_rank = tier_config.priority(required_name)

            if assigned_rank > required_rank and assigned_cost > required_cost:
                monthly_savings = round(assigned_cost - required_cost, 2)
                over_licensed_users.append(
                    {
                        "user_id": user_id,
                        "user_name": "REDACTED" if redact_pii else user_name,
                        "assigned_tier": assigned_name,
                        "required_tier": required_name,
                        "monthly_savings": monthly_savings,
                        "annual_savings": round(monthly_savings * 12, 2),
                    }
                )

    total_monthly_savings = sum(u["monthly_savings"] for u in over_licensed_users)
    total_annual_savings = round(total_monthly_savings * 12, 2)

    # Build warning for degraded modes
    warning: str | None = None
    if is_assess_only:
        warning = (
            "No external licence source configured. Results compare role-based "
            "requirements against themselves — real savings require configuring a "
            "licence source (graph, ppac, or file). Call get_security_server_config "
            "for setup guidance."
        )
    else:
        warning = _build_stale_warning(provider, stale_threshold_days)

    return ToolResponse(
        result={
            "warning": warning,
            "over_licensed_count": len(over_licensed_users),
            "total_annual_savings": total_annual_savings,
            "users": over_licensed_users,
            "mode": mode,
        },
        metadata=ResponseMetadata(
            duration_ms=int((time.monotonic() - started_at) * 1000),
            provider=provider.provider_name(),
            environment=getattr(client, "environment", ""),
        ),
        warnings=warnings,
    )
