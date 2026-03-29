from __future__ import annotations

import logging
import time
from typing import Any

from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.tools.assess import assess_all_users
from d365fo_security_mcp.tools.over_licensed import detect_over_licensed
from d365fo_security_mcp.tools.under_licensed import detect_under_licensed

logger = logging.getLogger(__name__)


async def get_licence_summary(
    client,
    tier_config: LicenceTierConfig,
    provider,
    *,
    redact_pii: bool = False,
    batch_size: int = 50,
) -> ToolResponse:
    """Return an aggregated licence cost and tier-breakdown summary.

    When *provider* is assess-only, over/under counts and savings opportunity
    are omitted (set to ``None``).  For all other providers a live comparison
    is performed and the full set of metrics is returned.
    """
    start = time.monotonic()
    warnings: list[str] = []

    # ------------------------------------------------------------------
    # 1. Obtain per-user role assessments.
    # ------------------------------------------------------------------
    assessment_response: ToolResponse = await assess_all_users(
        client,
        tier_config,
        redact_pii=redact_pii,
        batch_size=batch_size,
    )
    warnings.extend(assessment_response.warnings)

    assessments: list[dict[str, Any]] = (assessment_response.result or {}).get("assessments", [])
    total_users: int = len(assessments)

    # ------------------------------------------------------------------
    # 2. Group users by required tier and accumulate counts.
    # ------------------------------------------------------------------
    tier_user_counts: dict[str, int] = {}
    for assessment in assessments:
        required_tier = assessment.get("required_tier")
        tier_name = "None" if required_tier is None else required_tier.get("name", "None")
        tier_user_counts[tier_name] = tier_user_counts.get(tier_name, 0) + 1

    # ------------------------------------------------------------------
    # 3. Build the tier breakdown list.
    # ------------------------------------------------------------------
    tier_breakdown: list[dict[str, Any]] = []
    for tier in tier_config.tiers:
        user_count = tier_user_counts.get(tier.name, 0)
        if user_count == 0:
            continue
        monthly_cost = float(tier.monthly_cost) * user_count
        tier_breakdown.append(
            {
                "tier_name": tier.name,
                "display_name": tier.display_name,
                "user_count": user_count,
                "unit_monthly_cost": float(tier.monthly_cost),
                "monthly_cost": round(monthly_cost, 2),
                "annual_cost": round(monthly_cost * 12, 2),
            }
        )

    # ------------------------------------------------------------------
    # 4. Roll up totals.
    # ------------------------------------------------------------------
    total_monthly_cost: float = round(sum(entry["monthly_cost"] for entry in tier_breakdown), 2)
    total_annual_cost: float = round(total_monthly_cost * 12, 2)

    # ------------------------------------------------------------------
    # 5. Over / under licensed counts and savings opportunity.
    # ------------------------------------------------------------------
    is_assess_only: bool = provider.provider_name() == "assess-only"

    over_licensed_count: int | None = None
    under_licensed_count: int | None = None
    savings_opportunity: float | None = None

    if not is_assess_only:
        try:
            over_response: ToolResponse = await detect_over_licensed(
                client,
                tier_config,
                provider,
                redact_pii=redact_pii,
                batch_size=batch_size,
            )
            over_data: dict[str, Any] = over_response.result or {}
            over_licensed_count = over_data.get("over_licensed_count", 0)
            savings_opportunity = over_data.get("total_annual_savings", 0.0)
            warnings.extend(over_response.warnings)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not determine over-licensed count: {exc}")

        try:
            under_response: ToolResponse = await detect_under_licensed(
                client,
                tier_config,
                provider,
                redact_pii=redact_pii,
                batch_size=batch_size,
            )
            under_data: dict[str, Any] = under_response.result or {}
            under_licensed_count = under_data.get("under_licensed_count", 0)
            warnings.extend(under_response.warnings)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not determine under-licensed count: {exc}")

    # ------------------------------------------------------------------
    # 6. Build compact user_list sorted by tier priority (desc) then name (asc).
    # ------------------------------------------------------------------
    user_list: list[dict[str, Any]] = []
    for assessment in assessments:
        required_tier_info = assessment.get("required_tier")
        tier_display = (
            "No licence required"
            if required_tier_info is None
            else required_tier_info.get("display_name", "Unknown")
        )
        tier_name = "None" if required_tier_info is None else required_tier_info.get("name", "None")

        # Find the driving role name from the roles list
        driving_role_name: str | None = None
        roles = assessment.get("roles", [])
        for role in roles:
            if role.get("is_driving") is True:
                driving_role_name = role.get("role_name")
                break

        user_list.append(
            {
                "user_id": assessment.get("user_id", ""),
                "user_name": assessment.get("user_name", ""),
                "required_tier": tier_display,
                "driving_role": driving_role_name,
                "role_count": assessment.get("role_count", 0),
                "_tier_name": tier_name,  # internal, for sorting only
            }
        )

    # Sort: highest tier priority first, then alphabetically by user_name
    user_list.sort(
        key=lambda u: (-tier_config.priority(u["_tier_name"]), u["user_name"].lower()),
    )

    # Remove internal sort key
    for entry in user_list:
        del entry["_tier_name"]

    # ------------------------------------------------------------------
    # 7. Assemble result payload.
    # ------------------------------------------------------------------
    result: dict[str, Any] = {
        "total_users": total_users,
        "total_monthly_cost": total_monthly_cost,
        "total_annual_cost": total_annual_cost,
        "currency": tier_config.currency,
        "tier_breakdown": tier_breakdown,
        "over_licensed_count": over_licensed_count,
        "under_licensed_count": under_licensed_count,
        "savings_opportunity": savings_opportunity,
        "user_list": user_list,
    }

    duration_ms = round((time.monotonic() - start) * 1000)
    metadata = ResponseMetadata(
        duration_ms=duration_ms,
        environment=getattr(client, "environment", ""),
        currency=tier_config.currency,
    )

    return ToolResponse(result=result, metadata=metadata, warnings=warnings)
