"""get_high_risk_users — rank users by SoD violation count and severity."""

from __future__ import annotations

import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.sod.violations import detect_sod_violations


async def get_high_risk_users(
    client: ODataClient,
    ruleset: SodRuleset | None,
    *,
    top: int = 0,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> ToolResponse:
    """Rank users by SoD violation count and severity.

    Runs a full SoD scan, then sorts users by risk score (descending)
    and optionally limits to the top N.
    """
    start = time.perf_counter()

    # Delegate to detect_sod_violations for the heavy lifting
    scan_result = await detect_sod_violations(
        client, ruleset, redact_pii=redact_pii, exclude_service_accounts=exclude_service_accounts
    )

    if scan_result.result is None:
        return scan_result  # Propagate no-ruleset error

    users: list[dict[str, Any]] = scan_result.result.get("users", [])

    # Already sorted by risk score from detect_sod_violations
    if top > 0:
        users = users[:top]

    duration_ms = int((time.perf_counter() - start) * 1000)

    result: dict[str, Any] = {
        "high_risk_count": len(users),
        "users_scanned": scan_result.result.get("users_scanned", 0),
        "service_accounts_excluded": scan_result.result.get("service_accounts_excluded", 0),
        "users": users,
    }

    if not users:
        result["message"] = "No SoD violations detected in the environment."

    return ToolResponse(
        result=result,
        metadata=ResponseMetadata(
            provider="sod",
            environment=client.environment,
            duration_ms=duration_ms,
            currency="",
        ),
        warnings=scan_result.warnings,
    )
