"""Licence tier models and configuration."""

from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

from pydantic import BaseModel, Field, computed_field


class LicenceTier(BaseModel):
    """A D365 F&O licence classification level."""

    enum_value: int = Field(description="UserLicenseType enum value (0–12)")
    name: str = Field(description="Internal name from D365 enum")
    display_name: str = Field(description="Business-friendly display name")
    monthly_cost: Decimal = Field(
        default=Decimal("0.00"), description="Monthly cost in configured currency"
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def annual_cost(self) -> Decimal:
        """Annual cost (monthly × 12)."""
        return self.monthly_cost * 12


# Default licence tiers with Microsoft published list pricing (GBP, March 2026)
DEFAULT_LICENCE_TIERS: list[LicenceTier] = [
    LicenceTier(
        enum_value=0, name="None", display_name="No licence required", monthly_cost=Decimal("0.00")
    ),
    LicenceTier(
        enum_value=1, name="SelfServe", display_name="Self-Service", monthly_cost=Decimal("0.00")
    ),
    LicenceTier(
        enum_value=5,
        name="Server",
        display_name="Server / Service Account",
        monthly_cost=Decimal("0.00"),
    ),
    LicenceTier(
        enum_value=6, name="Universal", display_name="Team Member", monthly_cost=Decimal("5.80")
    ),
    LicenceTier(
        enum_value=7, name="Activity", display_name="Activity", monthly_cost=Decimal("25.30")
    ),
    LicenceTier(enum_value=2, name="Task", display_name="Task", monthly_cost=Decimal("30.00")),
    LicenceTier(
        enum_value=3,
        name="Functional",
        display_name="Functional (Legacy)",
        monthly_cost=Decimal("100.00"),
    ),
    LicenceTier(
        enum_value=12, name="HR", display_name="Human Resources", monthly_cost=Decimal("100.00")
    ),
    LicenceTier(
        enum_value=11,
        name="Project",
        display_name="Project Operations",
        monthly_cost=Decimal("100.00"),
    ),
    LicenceTier(
        enum_value=10, name="Commerce", display_name="Commerce", monthly_cost=Decimal("135.00")
    ),
    LicenceTier(
        enum_value=4,
        name="Enterprise",
        display_name="Finance / SCM (Legacy)",
        monthly_cost=Decimal("135.70"),
    ),
    LicenceTier(
        enum_value=8, name="Finance", display_name="Finance", monthly_cost=Decimal("135.70")
    ),
    LicenceTier(
        enum_value=9,
        name="SCM",
        display_name="Supply Chain Management",
        monthly_cost=Decimal("135.70"),
    ),
]


class LicenceTierConfig(BaseModel):
    """Configuration for licence tier ordering and cost bands.

    Priority is auto-derived from cost: highest cost = highest priority.
    """

    currency: str = Field(default="GBP", description="ISO 4217 currency code")
    tiers: list[LicenceTier] = Field(default_factory=lambda: list(DEFAULT_LICENCE_TIERS))

    # Lookup caches built on validation
    _by_name: dict[str, LicenceTier] = {}
    _by_enum: dict[int, LicenceTier] = {}
    _priority: dict[str, int] = {}

    NONE_TIER: ClassVar[LicenceTier] = LicenceTier(
        enum_value=0,
        name="None",
        display_name="No licence required",
        monthly_cost=Decimal("0.00"),
    )

    def model_post_init(self, _context: object) -> None:
        """Build lookup caches after initialisation."""
        sorted_tiers = sorted(self.tiers, key=lambda t: t.monthly_cost)
        self._by_name = {t.name: t for t in self.tiers}
        self._by_enum = {t.enum_value: t for t in self.tiers}
        self._priority = {t.name: idx for idx, t in enumerate(sorted_tiers)}

    def get_by_name(self, name: str) -> LicenceTier:
        """Look up a tier by its internal name. Returns None tier if not found."""
        return self._by_name.get(name, self.NONE_TIER)

    def get_by_enum(self, enum_value: int) -> LicenceTier:
        """Look up a tier by its enum value. Returns None tier if not found."""
        return self._by_enum.get(enum_value, self.NONE_TIER)

    def priority(self, tier_name: str) -> int:
        """Get the priority rank for a tier name (higher = more expensive)."""
        return self._priority.get(tier_name, 0)

    def highest_tier(self, tier_names: list[str]) -> LicenceTier:
        """Return the highest-priority tier from a list of tier names."""
        if not tier_names:
            return self.NONE_TIER
        best_name = max(tier_names, key=lambda n: self.priority(n))
        return self.get_by_name(best_name)

    @property
    def valid_tier_names(self) -> list[str]:
        """Return sorted list of all tier internal names (13 tiers)."""
        return sorted(self._by_name.keys())

    def cost_delta(self, from_tier: LicenceTier, to_tier: LicenceTier) -> Decimal:
        """Calculate monthly cost difference (negative = saving)."""
        return to_tier.monthly_cost - from_tier.monthly_cost
