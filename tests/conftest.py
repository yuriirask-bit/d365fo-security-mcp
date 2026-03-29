import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.models.config import ServerConfig
from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider

# ---------------------------------------------------------------------------
# --live flag and marker
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Run live tests against a real D365 F&O environment (requires env vars)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live: mark test as requiring a live D365 F&O environment"
        " — skipped unless --live is passed",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not config.getoption("--live"):
        skip_live = pytest.mark.skip(reason="Pass --live to run against a real D365 environment")
        for item in items:
            if item.get_closest_marker("live"):
                item.add_marker(skip_live)


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the tests/fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_roles(fixtures_dir: Path) -> list[dict]:
    """Load security roles fixture data."""
    with open(fixtures_dir / "security_roles.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def sample_duties(fixtures_dir: Path) -> list[dict]:
    """Load security duties fixture data."""
    with open(fixtures_dir / "security_duties.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def sample_assignments(fixtures_dir: Path) -> list[dict]:
    """Load user role assignments fixture data."""
    with open(fixtures_dir / "user_role_assignments.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def sample_users(fixtures_dir: Path) -> list[dict]:
    """Load system users fixture data."""
    with open(fixtures_dir / "system_users.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def tier_config() -> LicenceTierConfig:
    """Return a LicenceTierConfig instance with default settings."""
    return LicenceTierConfig()


@pytest.fixture
def assess_only_provider() -> AssessOnlyProvider:
    """Return an AssessOnlyProvider instance."""
    return AssessOnlyProvider()


@pytest.fixture
def sample_privileges(fixtures_dir: Path) -> list[dict]:
    """Load security privileges fixture data."""
    with open(fixtures_dir / "security_privileges.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def mock_odata_client(
    sample_roles: list[dict],
    sample_assignments: list[dict],
    sample_duties: list[dict],
    sample_privileges: list[dict],
    sample_users: list[dict],
) -> MagicMock:
    """
    Return a MagicMock OData client whose async ``query`` method returns
    fixture data matched by entity name.

    Routing rules:
    - Entity contains "SecurityRoles"          → sample_roles
    - Entity contains "UserRoleAssociations"
      or "SecurityUserRole"                    → sample_assignments (filtered
                                                 by UserId when filter_expr
                                                 contains "UserId eq")
    - Entity contains "SecurityRoleDuties"
      or "SecurityDuties"                      → sample_duties (filtered by
                                                 SecurityRoleIdentifier when
                                                 filter_expr is present)
    - Entity contains "SecurityPrivileges"     → sample_privileges (filtered by
                                                 SecurityRoleIdentifier when
                                                 filter_expr is present)
    - Entity contains "SystemUsers"            → sample_users
    """

    def _extract_quoted_value(filter_expr: str, field: str) -> str | None:
        """Pull the value from a simple ``field eq 'value'`` filter clause."""
        needle = f"{field} eq '"
        idx = filter_expr.find(needle)
        if idx == -1:
            return None
        start = idx + len(needle)
        end = filter_expr.find("'", start)
        return filter_expr[start:end] if end != -1 else None

    async def _query(entity: str, filter_expr: str = "", **kwargs) -> list[dict]:
        if "SecurityRoles" in entity:
            if filter_expr and "SecurityRoleIdentifier eq" in filter_expr:
                role_id = _extract_quoted_value(filter_expr, "SecurityRoleIdentifier")
                if role_id is not None:
                    return [r for r in sample_roles if r["SecurityRoleIdentifier"] == role_id]
            return list(sample_roles)

        if "UserRoleAssociations" in entity or "SecurityUserRole" in entity:
            if filter_expr and "UserId eq" in filter_expr:
                user_id = _extract_quoted_value(filter_expr, "UserId")
                if user_id is not None:
                    return [r for r in sample_assignments if r["UserId"] == user_id]
            return list(sample_assignments)

        if "SecurityRoleDuties" in entity or "SecurityDuties" in entity:
            if filter_expr:
                role_id = _extract_quoted_value(filter_expr, "SecurityRoleIdentifier")
                if role_id is not None:
                    return [d for d in sample_duties if d["SecurityRoleIdentifier"] == role_id]
            return list(sample_duties)

        if "SecurityPrivileges" in entity:
            if filter_expr:
                role_id = _extract_quoted_value(filter_expr, "SecurityRoleIdentifier")
                if role_id is not None:
                    return [p for p in sample_privileges if p["SecurityRoleIdentifier"] == role_id]
            return list(sample_privileges)

        if "SystemUsers" in entity:
            return list(sample_users)

        return []

    client = MagicMock()
    client.query = AsyncMock(side_effect=_query)
    client.close = AsyncMock(return_value=None)
    client.environment = "test.operations.dynamics.com"
    return client


@pytest.fixture
def server_config() -> ServerConfig:
    """Return a ServerConfig instance with default settings."""
    return ServerConfig()
