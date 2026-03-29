"""SoD ruleset JSON file loader and validator."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodRuleset,
    SodRulesetMetadata,
)

logger = logging.getLogger(__name__)


def load_ruleset(file_path: str) -> tuple[SodRuleset, list[str]]:
    """Load and validate an SoD conflict ruleset from a JSON file.

    Returns a tuple of (validated ruleset, warnings).  Invalid rules are
    skipped with a warning rather than failing the entire load.
    """
    warnings: list[str] = []
    path = Path(file_path).resolve()

    # Validate file extension
    if path.suffix.lower() not in {".json"}:
        raise ValueError(f"SoD ruleset file must be a .json file, got: {path.suffix}")

    if not path.exists():
        raise FileNotFoundError(
            f"SoD ruleset file not found: {file_path}. "
            "Set SOD_RULES_FILE to the path of your SoD conflict ruleset JSON file."
        )

    # Guard against excessively large files (max 10 MB)
    file_size = path.stat().st_size
    if file_size > 10 * 1024 * 1024:
        raise ValueError(f"SoD ruleset file exceeds 10 MB size limit ({file_size} bytes).")

    try:
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"SoD ruleset file is not valid JSON: {file_path} — {exc}") from exc

    # Parse metadata
    version = raw.get("version", "")
    if not version:
        warnings.append("Ruleset file missing 'version' field; assuming '1.0'.")
        version = "1.0"

    raw_meta = raw.get("metadata", {})
    try:
        metadata = SodRulesetMetadata(
            name=raw_meta.get("name", path.stem),
            description=raw_meta.get("description", ""),
            author=raw_meta.get("author", ""),
            created=raw_meta.get("created", ""),
            version=version,
        )
    except ValidationError as exc:
        raise ValueError(f"Invalid ruleset metadata: {exc}") from exc

    # Parse privileged roles
    privileged_roles: list[str] = raw.get("privileged_roles", [])
    if not isinstance(privileged_roles, list):
        warnings.append("'privileged_roles' is not a list; ignoring.")
        privileged_roles = []

    # Parse and validate individual rules
    raw_rules: list[dict[str, Any]] = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        warnings.append("'rules' is not a list; no rules loaded.")
        raw_rules = []

    valid_rules: list[SodConflictRule] = []
    seen_ids: set[str] = set()

    for idx, rule_data in enumerate(raw_rules):
        rule_id = rule_data.get("id", f"<rule at index {idx}>")

        # Duplicate ID check
        if rule_id in seen_ids:
            warnings.append(f"Duplicate rule ID '{rule_id}' at index {idx}; skipping duplicate.")
            continue

        try:
            rule = SodConflictRule.model_validate(rule_data)
            valid_rules.append(rule)
            seen_ids.add(rule_id)
        except ValidationError as exc:
            warnings.append(f"Invalid rule '{rule_id}' at index {idx}: {exc}. Skipping.")

    if not valid_rules:
        warnings.append("No valid rules found in the ruleset file.")

    # Compute metadata counts
    categories = {r.category for r in valid_rules}
    metadata.rule_count = len(valid_rules)
    metadata.category_count = len(categories)

    ruleset = SodRuleset(
        metadata=metadata,
        privileged_roles=privileged_roles,
        rules=valid_rules,
    )

    logger.info(
        "Loaded SoD ruleset '%s': %d rules across %d categories",
        metadata.name,
        metadata.rule_count,
        metadata.category_count,
    )

    return ruleset, warnings
