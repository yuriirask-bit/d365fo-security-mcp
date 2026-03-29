"""get_sod_conflict_matrix — return the loaded SoD ruleset for inspection."""

from __future__ import annotations

import time
from typing import Any

from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.models.sod import SodRuleset


async def get_sod_conflict_matrix(
    ruleset: SodRuleset | None,
    *,
    category: str = "",
) -> ToolResponse:
    """Return the configured SoD conflict ruleset, optionally filtered by category.

    Args:
        ruleset: The loaded SoD conflict ruleset. None if not configured.
        category: Filter to a specific category slug. Empty = all rules.

    Returns:
        ToolResponse with the ruleset rules and metadata.
    """
    start = time.perf_counter()
    warnings: list[str] = []

    if ruleset is None:
        return ToolResponse(
            result=None,
            metadata=ResponseMetadata(provider="sod", environment="", duration_ms=0, currency=""),
            warnings=[
                "No SoD ruleset configured. "
                "Set SOD_RULES_FILE to the path of your SoD conflict "
                "ruleset JSON file."
            ],
        )

    rules = ruleset.rules

    # Apply category filter
    if category:
        available_categories = sorted({r.category for r in ruleset.rules})
        filtered = [r for r in rules if r.category == category]
        if not filtered and category not in available_categories:
            warnings.append(
                f"Unknown category '{category}'. "
                f"Available categories: {', '.join(available_categories)}"
            )
        rules = filtered

    duration_ms = int((time.perf_counter() - start) * 1000)

    result: dict[str, Any] = {
        "ruleset_name": ruleset.metadata.name,
        "version": ruleset.metadata.version,
        "rule_count": len(rules),
        "categories": sorted({r.category for r in ruleset.rules}),
        "rules": [r.model_dump() for r in rules],
    }

    return ToolResponse(
        result=result,
        metadata=ResponseMetadata(
            provider="sod", environment="", duration_ms=duration_ms, currency=""
        ),
        warnings=warnings,
    )
