"""Unit tests for SoD ruleset loader and validator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d365fo_security_mcp.tools.sod.ruleset import load_ruleset


def _write_json(data: dict, path: Path) -> str:
    """Write JSON data to a temp file and return the path string."""
    file_path = path / "rules.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")
    return str(file_path)


def _minimal_ruleset(**overrides) -> dict:
    """Return a minimal valid ruleset dict."""
    base = {
        "version": "1.0",
        "metadata": {"name": "Test", "version": "1.0"},
        "rules": [
            {
                "id": "SOD-001",
                "name": "Test Rule",
                "category": "test",
                "risk_level": "High",
                "description": "Test conflict",
                "duty_group_a": {"name": "Group A", "duties": ["DutyA"]},
                "duty_group_b": {"name": "Group B", "duties": ["DutyB"]},
            }
        ],
    }
    base.update(overrides)
    return base


class TestLoadRulesetValid:
    def test_valid_ruleset_loads_successfully(self, tmp_path: Path) -> None:
        path = _write_json(_minimal_ruleset(), tmp_path)
        ruleset, warnings = load_ruleset(path)

        assert ruleset.metadata.name == "Test"
        assert ruleset.metadata.rule_count == 1
        assert ruleset.metadata.category_count == 1
        assert len(ruleset.rules) == 1
        assert ruleset.rules[0].id == "SOD-001"
        assert warnings == []

    def test_ruleset_with_privileged_roles(self, tmp_path: Path) -> None:
        data = _minimal_ruleset(privileged_roles=["-SYSADMIN-", "SECADMIN"])
        path = _write_json(data, tmp_path)
        ruleset, _ = load_ruleset(path)

        assert ruleset.privileged_roles == ["-SYSADMIN-", "SECADMIN"]

    def test_multiple_rules_across_categories(self, tmp_path: Path) -> None:
        data = _minimal_ruleset()
        data["rules"].append(
            {
                "id": "SOD-002",
                "name": "Second Rule",
                "category": "other_category",
                "risk_level": "Critical",
                "description": "Another conflict",
                "duty_group_a": {"name": "X", "duties": ["DutyX"]},
                "duty_group_b": {"name": "Y", "duties": ["DutyY"]},
            }
        )
        path = _write_json(data, tmp_path)
        ruleset, warnings = load_ruleset(path)

        assert ruleset.metadata.rule_count == 2
        assert ruleset.metadata.category_count == 2
        assert warnings == []


class TestLoadRulesetMissingFile:
    def test_missing_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_ruleset("/nonexistent/path/rules.json")


class TestLoadRulesetMalformed:
    def test_invalid_json_raises_value_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json {{{", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            load_ruleset(str(path))

    def test_missing_version_adds_warning(self, tmp_path: Path) -> None:
        data = _minimal_ruleset()
        del data["version"]
        path = _write_json(data, tmp_path)
        _, warnings = load_ruleset(path)

        assert any("missing 'version'" in w for w in warnings)

    def test_invalid_rule_skipped_with_warning(self, tmp_path: Path) -> None:
        data = _minimal_ruleset()
        data["rules"].append({"id": "BAD", "name": "Missing fields"})
        path = _write_json(data, tmp_path)
        ruleset, warnings = load_ruleset(path)

        assert ruleset.metadata.rule_count == 1  # only valid rule kept
        assert any("Invalid rule 'BAD'" in w for w in warnings)

    def test_empty_rules_list_adds_warning(self, tmp_path: Path) -> None:
        data = _minimal_ruleset(rules=[])
        path = _write_json(data, tmp_path)
        _, warnings = load_ruleset(path)

        assert any("No valid rules" in w for w in warnings)


class TestLoadRulesetDuplicateIds:
    def test_duplicate_rule_id_skipped_with_warning(self, tmp_path: Path) -> None:
        data = _minimal_ruleset()
        data["rules"].append(
            {
                "id": "SOD-001",  # duplicate
                "name": "Duplicate Rule",
                "category": "test",
                "risk_level": "Medium",
                "description": "Dup",
                "duty_group_a": {"name": "A", "duties": ["X"]},
                "duty_group_b": {"name": "B", "duties": ["Y"]},
            }
        )
        path = _write_json(data, tmp_path)
        ruleset, warnings = load_ruleset(path)

        assert ruleset.metadata.rule_count == 1
        assert any("Duplicate rule ID" in w for w in warnings)
