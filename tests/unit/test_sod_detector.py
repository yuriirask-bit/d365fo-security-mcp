"""Unit tests for SoD detection engine."""

from __future__ import annotations

from d365fo_security_mcp.models.sod import (
    SodConflictRule,
    SodDutyGroup,
    SodRuleset,
    SodRulesetMetadata,
)
from d365fo_security_mcp.tools.sod.detector import (
    build_effective_duties,
    build_role_duty_map,
    build_sub_role_map,
    detect_for_user,
    detect_violations,
    resolve_sub_roles,
)


def _rule(
    rule_id: str = "SOD-001",
    duties_a: list[str] | None = None,
    duties_b: list[str] | None = None,
    risk_level: str = "High",
) -> SodConflictRule:
    return SodConflictRule(
        id=rule_id,
        name=f"Rule {rule_id}",
        category="test",
        risk_level=risk_level,
        description="Test conflict",
        duty_group_a=SodDutyGroup(name="A", duties=duties_a or ["DutyA"]),
        duty_group_b=SodDutyGroup(name="B", duties=duties_b or ["DutyB"]),
    )


def _ruleset(rules: list[SodConflictRule] | None = None) -> SodRuleset:
    rules = rules or [_rule()]
    return SodRuleset(
        metadata=SodRulesetMetadata(name="Test", version="1.0"),
        rules=rules,
    )


class TestResolveSubRoles:
    def test_no_sub_roles_returns_assigned(self) -> None:
        result = resolve_sub_roles({"RoleA"}, {})
        assert result == {"RoleA"}

    def test_single_level_sub_role(self) -> None:
        sub_map = {"RoleA": ["RoleB"]}
        result = resolve_sub_roles({"RoleA"}, sub_map)
        assert result == {"RoleA", "RoleB"}

    def test_multi_level_sub_roles(self) -> None:
        sub_map = {"RoleA": ["RoleB"], "RoleB": ["RoleC"]}
        result = resolve_sub_roles({"RoleA"}, sub_map)
        assert result == {"RoleA", "RoleB", "RoleC"}

    def test_circular_sub_roles_handled(self) -> None:
        sub_map = {"RoleA": ["RoleB"], "RoleB": ["RoleA"]}
        result = resolve_sub_roles({"RoleA"}, sub_map)
        assert result == {"RoleA", "RoleB"}

    def test_multiple_assigned_roles_merged(self) -> None:
        sub_map = {"RoleA": ["RoleC"], "RoleB": ["RoleC"]}
        result = resolve_sub_roles({"RoleA", "RoleB"}, sub_map)
        assert result == {"RoleA", "RoleB", "RoleC"}


class TestBuildEffectiveDuties:
    def test_duties_from_single_role(self) -> None:
        role_duty_map = {"RoleA": ["D1", "D2"]}
        result = build_effective_duties({"RoleA"}, role_duty_map)
        assert result == {"D1", "D2"}

    def test_duties_deduplicated_across_roles(self) -> None:
        role_duty_map = {"RoleA": ["D1", "D2"], "RoleB": ["D2", "D3"]}
        result = build_effective_duties({"RoleA", "RoleB"}, role_duty_map)
        assert result == {"D1", "D2", "D3"}

    def test_role_with_no_duties(self) -> None:
        result = build_effective_duties({"RoleA"}, {})
        assert result == set()


class TestDetectViolations:
    def test_single_violation_detected(self) -> None:
        user_duties = {"DutyA", "DutyB"}
        duty_to_roles = {"DutyA": ["R1"], "DutyB": ["R2"]}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset())

        assert len(violations) == 1
        assert violations[0].rule_id == "SOD-001"
        assert violations[0].matched_duties_a == ["DutyA"]
        assert violations[0].matched_duties_b == ["DutyB"]

    def test_no_violation_when_only_one_side_matched(self) -> None:
        user_duties = {"DutyA", "DutyC"}
        duty_to_roles = {"DutyA": ["R1"], "DutyC": ["R2"]}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset())

        assert len(violations) == 0

    def test_no_violation_when_no_duties_match(self) -> None:
        user_duties = {"DutyX", "DutyY"}
        duty_to_roles = {}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset())

        assert len(violations) == 0

    def test_any_to_any_matching(self) -> None:
        """One duty from group A + one from group B triggers violation."""
        rule = _rule(duties_a=["D1", "D2"], duties_b=["D3", "D4"])
        user_duties = {"D1", "D4"}  # one from each side
        duty_to_roles = {"D1": ["R1"], "D4": ["R2"]}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset([rule]))

        assert len(violations) == 1
        assert violations[0].matched_duties_a == ["D1"]
        assert violations[0].matched_duties_b == ["D4"]

    def test_multiple_violations_across_rules(self) -> None:
        rules = [
            _rule("SOD-001", duties_a=["D1"], duties_b=["D2"]),
            _rule("SOD-002", duties_a=["D3"], duties_b=["D4"], risk_level="Critical"),
        ]
        user_duties = {"D1", "D2", "D3", "D4"}
        duty_to_roles = {"D1": ["R1"], "D2": ["R2"], "D3": ["R3"], "D4": ["R4"]}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset(rules))

        assert len(violations) == 2

    def test_granting_roles_populated(self) -> None:
        user_duties = {"DutyA", "DutyB"}
        duty_to_roles = {"DutyA": ["RoleX", "RoleY"], "DutyB": ["RoleZ"]}
        violations = detect_violations(user_duties, duty_to_roles, _ruleset())

        assert violations[0].granting_roles_a == ["RoleX", "RoleY"]
        assert violations[0].granting_roles_b == ["RoleZ"]


class TestDetectForUser:
    def test_full_detection_pipeline(self) -> None:
        role_duty_map = {"RoleA": ["DutyA"], "RoleB": ["DutyB"]}
        sub_role_map: dict[str, list[str]] = {}

        result = detect_for_user(
            user_id="jsmith",
            user_name="John Smith",
            assigned_role_ids={"RoleA", "RoleB"},
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=_ruleset(),
        )

        assert result.user_id == "jsmith"
        assert result.violation_count == 1
        assert result.highest_severity == "High"
        assert result.risk_score == 2.0

    def test_sub_role_duties_included(self) -> None:
        role_duty_map = {"RoleA": ["DutyA"], "RoleC": ["DutyB"]}
        sub_role_map = {"RoleA": ["RoleC"]}

        result = detect_for_user(
            user_id="jsmith",
            user_name="John Smith",
            assigned_role_ids={"RoleA"},  # only RoleA assigned directly
            role_duty_map=role_duty_map,
            sub_role_map=sub_role_map,
            ruleset=_ruleset(),
        )

        # DutyB comes via sub-role RoleC
        assert result.violation_count == 1

    def test_no_violations_clean_user(self) -> None:
        role_duty_map = {"RoleA": ["DutyA"]}
        result = detect_for_user(
            user_id="clean",
            user_name="Clean User",
            assigned_role_ids={"RoleA"},
            role_duty_map=role_duty_map,
            sub_role_map={},
            ruleset=_ruleset(),
        )

        assert result.violation_count == 0
        assert result.highest_severity == "None"
        assert result.risk_score == 0.0


class TestBuildMaps:
    def test_build_sub_role_map(self) -> None:
        data = [
            {"SecurityRoleIdentifier": "P", "SecuritySubRoleIdentifier": "C1"},
            {"SecurityRoleIdentifier": "P", "SecuritySubRoleIdentifier": "C2"},
        ]
        result = build_sub_role_map(data)
        assert result == {"P": ["C1", "C2"]}

    def test_build_role_duty_map(self) -> None:
        data = [
            {"SecurityRoleIdentifier": "R1", "SecurityDutyIdentifier": "D1"},
            {"SecurityRoleIdentifier": "R1", "SecurityDutyIdentifier": "D2"},
            {"SecurityRoleIdentifier": "R2", "SecurityDutyIdentifier": "D3"},
        ]
        result = build_role_duty_map(data)
        assert result == {"R1": ["D1", "D2"], "R2": ["D3"]}
