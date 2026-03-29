"""Pydantic models for SoD conflict detection and security analysis."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Ruleset models (loaded from external JSON file)
# ---------------------------------------------------------------------------


class SodDutyGroup(BaseModel):
    """One side of a conflict rule — a named group of duty identifiers."""

    name: str = Field(description="Human-readable name, e.g. 'Maintain vendor master'")
    duties: list[str] = Field(
        description="D365 duty identifiers, e.g. ['VendTableMaintain']",
        min_length=1,
    )


class SodConflictRule(BaseModel):
    """A single SoD conflict rule loaded from the external ruleset file."""

    id: str = Field(description="Unique rule identifier, e.g. 'SOD-AP-001'")
    name: str = Field(description="Human-readable rule name")
    category: str = Field(description="Category slug, e.g. 'accounts_payable'")
    risk_level: Literal["Critical", "High", "Medium"] = Field(
        description="Severity of the conflict"
    )
    description: str = Field(
        description="Plain-English explanation of why this combination is risky"
    )
    duty_group_a: SodDutyGroup = Field(description="First conflicting duty group")
    duty_group_b: SodDutyGroup = Field(description="Second conflicting duty group")


class SodRulesetMetadata(BaseModel):
    """Metadata about the loaded ruleset file."""

    name: str = Field(description="Ruleset name")
    description: str = Field(default="", description="Ruleset description")
    author: str = Field(default="", description="Who authored the ruleset")
    created: str = Field(default="", description="Creation date")
    version: str = Field(description="Schema version, e.g. '1.0'")
    rule_count: int = Field(default=0, description="Number of valid rules loaded")
    category_count: int = Field(default=0, description="Number of distinct categories")


class SodRuleset(BaseModel):
    """The complete loaded and validated ruleset."""

    metadata: SodRulesetMetadata = Field(description="Ruleset metadata")
    privileged_roles: list[str] = Field(
        default_factory=list,
        description="Curated list of privileged role identifiers",
    )
    rules: list[SodConflictRule] = Field(
        default_factory=list, description="All valid conflict rules"
    )


# ---------------------------------------------------------------------------
# Violation / detection result models
# ---------------------------------------------------------------------------


class SodViolation(BaseModel):
    """A detected violation instance for a specific user."""

    rule_id: str = Field(description="Reference to the conflict rule")
    rule_name: str = Field(description="Human-readable rule name")
    category: str = Field(description="Conflict category")
    risk_level: str = Field(description="Critical / High / Medium")
    description: str = Field(description="Why this is a risk")
    matched_duties_a: list[str] = Field(description="User's duties that matched group A")
    matched_duties_b: list[str] = Field(description="User's duties that matched group B")
    granting_roles_a: list[str] = Field(description="Roles that grant the matched group A duties")
    granting_roles_b: list[str] = Field(description="Roles that grant the matched group B duties")


class UserSodResult(BaseModel):
    """SoD scan result for a single user."""

    user_id: str = Field(description="D365 user identifier")
    user_name: str = Field(description="Display name (or redacted)")
    violation_count: int = Field(default=0, description="Number of violations")
    risk_score: float = Field(
        default=0.0,
        description="Weighted score (Critical=3, High=2, Medium=1)",
    )
    highest_severity: str = Field(default="None", description="Highest risk level among violations")
    violations: list[SodViolation] = Field(
        default_factory=list, description="All detected violations"
    )


# ---------------------------------------------------------------------------
# Health score models
# ---------------------------------------------------------------------------

_RISK_WEIGHTS: dict[str, float] = {"Critical": 3.0, "High": 2.0, "Medium": 1.0}


def compute_risk_score(violations: list[SodViolation]) -> float:
    """Compute weighted risk score from a list of violations."""
    return sum(_RISK_WEIGHTS.get(v.risk_level, 0.0) for v in violations)


def highest_severity(violations: list[SodViolation]) -> str:
    """Return the highest severity among violations, or 'None'."""
    priority = ["Critical", "High", "Medium"]
    for level in priority:
        if any(v.risk_level == level for v in violations):
            return level
    return "None"


class DimensionScore(BaseModel):
    """Score for a single health dimension."""

    name: str = Field(description="Dimension name, e.g. 'SoD Compliance'")
    score: int = Field(description="0–25 for this dimension")
    max_score: int = Field(default=25, description="Always 25")
    status: str = Field(description="'Healthy' / 'Warning' / 'Critical' / 'Unavailable'")
    detail: str = Field(description="Explanation of score")


class SecurityHealthScore(BaseModel):
    """Aggregate security posture score."""

    overall_score: int = Field(description="0–100 composite score")
    rating: str = Field(description="'Excellent' / 'Good' / 'Needs Attention' / 'Critical'")
    dimensions: dict[str, DimensionScore] = Field(description="Breakdown by dimension")
    recommendations: list[str] = Field(description="Plain-English action items")
