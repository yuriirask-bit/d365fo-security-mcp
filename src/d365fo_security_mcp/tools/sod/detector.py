"""Core SoD detection engine — ANY-to-ANY matching with sub-role resolution."""

from __future__ import annotations

import logging
from typing import Any

from d365fo_security_mcp.models.sod import (
    SodRuleset,
    SodViolation,
    UserSodResult,
    compute_risk_score,
    highest_severity,
)

logger = logging.getLogger(__name__)


def resolve_sub_roles(
    assigned_role_ids: set[str],
    sub_role_map: dict[str, list[str]],
) -> set[str]:
    """Recursively expand assigned roles to include all sub-roles.

    Args:
        assigned_role_ids: The user's directly assigned role identifiers.
        sub_role_map: Mapping of parent role ID → list of child role IDs.

    Returns:
        Full set of effective role IDs (assigned + all sub-roles).
    """
    effective: set[str] = set(assigned_role_ids)
    stack = list(assigned_role_ids)

    while stack:
        role_id = stack.pop()
        for child in sub_role_map.get(role_id, []):
            if child not in effective:
                effective.add(child)
                stack.append(child)

    return effective


def build_effective_duties(
    effective_role_ids: set[str],
    role_duty_map: dict[str, list[str]],
) -> set[str]:
    """Build a deduplicated set of duties from all effective roles.

    Args:
        effective_role_ids: All role IDs (including sub-roles).
        role_duty_map: Mapping of role ID → list of duty IDs.

    Returns:
        Deduplicated set of duty identifiers.
    """
    duties: set[str] = set()
    for role_id in effective_role_ids:
        duties.update(role_duty_map.get(role_id, []))
    return duties


def build_duty_to_roles(
    effective_role_ids: set[str],
    role_duty_map: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Build a reverse mapping: duty ID → list of granting role IDs."""
    result: dict[str, list[str]] = {}
    for role_id in effective_role_ids:
        for duty_id in role_duty_map.get(role_id, []):
            result.setdefault(duty_id, []).append(role_id)
    return result


def detect_violations(
    user_duties: set[str],
    duty_to_roles: dict[str, list[str]],
    ruleset: SodRuleset,
) -> list[SodViolation]:
    """Detect SoD violations for a single user using ANY-to-ANY matching.

    A violation triggers when the user holds at least one duty from
    group A and at least one duty from group B of a conflict rule.

    Args:
        user_duties: The user's effective duty set (deduplicated).
        duty_to_roles: Reverse mapping of duty → granting roles.
        ruleset: The loaded SoD conflict ruleset.

    Returns:
        List of violations detected for this user.
    """
    violations: list[SodViolation] = []

    for rule in ruleset.rules:
        matched_a = user_duties & set(rule.duty_group_a.duties)
        matched_b = user_duties & set(rule.duty_group_b.duties)

        if matched_a and matched_b:
            # Collect granting roles for matched duties
            roles_a: set[str] = set()
            for duty in matched_a:
                roles_a.update(duty_to_roles.get(duty, []))

            roles_b: set[str] = set()
            for duty in matched_b:
                roles_b.update(duty_to_roles.get(duty, []))

            violations.append(
                SodViolation(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    risk_level=rule.risk_level,
                    description=rule.description,
                    matched_duties_a=sorted(matched_a),
                    matched_duties_b=sorted(matched_b),
                    granting_roles_a=sorted(roles_a),
                    granting_roles_b=sorted(roles_b),
                )
            )

    return violations


def detect_for_user(
    user_id: str,
    user_name: str,
    assigned_role_ids: set[str],
    role_duty_map: dict[str, list[str]],
    sub_role_map: dict[str, list[str]],
    ruleset: SodRuleset,
) -> UserSodResult:
    """Run SoD detection for a single user.

    Resolves sub-roles, builds effective duty set, checks all rules.
    """
    effective_roles = resolve_sub_roles(assigned_role_ids, sub_role_map)
    user_duties = build_effective_duties(effective_roles, role_duty_map)
    duty_to_roles = build_duty_to_roles(effective_roles, role_duty_map)

    violations = detect_violations(user_duties, duty_to_roles, ruleset)

    return UserSodResult(
        user_id=user_id,
        user_name=user_name,
        violation_count=len(violations),
        risk_score=compute_risk_score(violations),
        highest_severity=highest_severity(violations),
        violations=violations,
    )


def build_sub_role_map(
    sub_roles_data: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Build parent → children sub-role map from OData query result.

    Expected fields per record: SecurityRoleIdentifier, SecuritySubRoleIdentifier.
    """
    result: dict[str, list[str]] = {}
    for row in sub_roles_data:
        parent = row.get("SecurityRoleIdentifier", "")
        child = row.get("SecuritySubRoleIdentifier", "")
        if parent and child:
            result.setdefault(parent, []).append(child)
    return result


def build_role_duty_map(
    duties_data: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Build role → duties map from OData query result.

    Expected fields per record: SecurityRoleIdentifier, SecurityDutyIdentifier.
    """
    result: dict[str, list[str]] = {}
    for row in duties_data:
        role_id = row.get("SecurityRoleIdentifier", "")
        duty_id = row.get("SecurityDutyIdentifier", "")
        if role_id and duty_id:
            result.setdefault(role_id, []).append(duty_id)
    return result
