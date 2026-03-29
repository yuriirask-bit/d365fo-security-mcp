from __future__ import annotations

from decimal import Decimal

import pytest

from d365fo_security_mcp.models.licence import LicenceTier, LicenceTierConfig


def test_tier_priority_derived_from_cost():
    config = LicenceTierConfig()
    assert config.priority("Enterprise") > config.priority("Activity")
    assert config.priority("Activity") > config.priority("Universal")
    assert config.priority("Universal") > config.priority("None")


def test_tier_config_custom_costs_override_defaults():
    custom_tiers = [
        LicenceTier(
            enum_value=4,
            name="Enterprise",
            monthly_cost=Decimal("100.00"),
            display_name="Finance and Operations",
        ),
        LicenceTier(
            enum_value=7,
            name="Activity",
            monthly_cost=Decimal("200.00"),
            display_name="Activity",
        ),
        LicenceTier(
            enum_value=6,
            name="Universal",
            monthly_cost=Decimal("10.00"),
            display_name="Team Member",
        ),
        LicenceTier(
            enum_value=0,
            name="None",
            monthly_cost=Decimal("0.00"),
            display_name="No Licence",
        ),
    ]
    config = LicenceTierConfig(tiers=custom_tiers)
    assert config.priority("Activity") > config.priority("Enterprise")


def test_tier_config_currency_code_configurable():
    config = LicenceTierConfig(currency="USD")
    assert config.currency == "USD"


def test_tier_display_name_business_friendly():
    config = LicenceTierConfig()
    enterprise_tier = config.get_by_name("Enterprise")
    activity_tier = config.get_by_name("Activity")
    universal_tier = config.get_by_name("Universal")

    assert "Finance" in enterprise_tier.display_name or "SCM" in enterprise_tier.display_name
    assert "Activity" in activity_tier.display_name
    assert "Team Member" in universal_tier.display_name


def test_highest_tier_returns_most_expensive():
    config = LicenceTierConfig()
    result = config.highest_tier(["None", "Activity", "Enterprise"])
    assert result.name == "Enterprise"


def test_highest_tier_empty_list_returns_none():
    config = LicenceTierConfig()
    result = config.highest_tier([])
    assert result.name == "None"


def test_cost_delta_calculates_savings():
    config = LicenceTierConfig()
    enterprise = config.get_by_name("Enterprise")
    activity = config.get_by_name("Activity")
    delta = config.cost_delta(enterprise, activity)
    assert delta < 0


def test_annual_cost_computed():
    tier = LicenceTier(
        enum_value=4,
        name="Enterprise",
        monthly_cost=Decimal("135.70"),
        display_name="Finance and Operations",
    )
    assert float(tier.annual_cost) == pytest.approx(1628.40, rel=1e-3)


def test_valid_tier_names_returns_all_13_tiers():
    config = LicenceTierConfig()
    names = config.valid_tier_names
    assert len(names) == 13
    assert "Enterprise" in names
    assert "Activity" in names
    assert "Universal" in names
    assert "None" in names
    assert "Finance" in names
    assert "SCM" in names
    assert "Commerce" in names
    assert "HR" in names
    assert "Project" in names
    assert "Task" in names
    assert "Functional" in names
    assert "SelfServe" in names
    assert "Server" in names


def test_valid_tier_names_sorted_alphabetically():
    config = LicenceTierConfig()
    names = config.valid_tier_names
    assert names == sorted(names)
