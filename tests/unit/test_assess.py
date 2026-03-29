"""Tests for d365fo_security_mcp.tools.assess — assess_user and assess_all_users."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from d365fo_security_mcp.tools.assess import assess_all_users, assess_user

# ---------------------------------------------------------------------------
# assess_user
# ---------------------------------------------------------------------------


class TestAssessUser:
    """Tests for the assess_user tool."""

    async def test_assess_user_enterprise_role_returns_enterprise_tier(
        self, mock_odata_client, tier_config
    ):
        """User 'admin' has SYSADMIN (Enterprise) — required tier should be Enterprise."""
        response = await assess_user(mock_odata_client, tier_config, "admin")

        assert response.result["user_id"] == "admin"
        assert response.result["required_tier"]["name"] == "Enterprise"
        assert response.result["required_tier"]["monthly_cost"] == 135.7
        assert response.result["role_count"] == 1
        assert response.warnings == []

    async def test_assess_user_mixed_tiers_returns_highest(self, mock_odata_client, tier_config):
        """User 'jsmith' has Enterprise + Activity roles — highest should win."""
        response = await assess_user(mock_odata_client, tier_config, "jsmith")

        assert response.result["user_id"] == "jsmith"
        assert response.result["required_tier"]["name"] == "Enterprise"
        assert response.result["role_count"] == 2

    async def test_assess_user_activity_only_returns_activity(self, mock_odata_client, tier_config):
        """User 'warehouse1' has only WHSWAREHOUSEWORKER (Activity)."""
        response = await assess_user(mock_odata_client, tier_config, "warehouse1")

        assert response.result["required_tier"]["name"] == "Activity"
        assert response.result["required_tier"]["monthly_cost"] == 25.3

    async def test_assess_user_universal_only_returns_universal(
        self, mock_odata_client, tier_config
    ):
        """User 'employee1' has only HCMEMPLOYEE (Universal / Team Member)."""
        response = await assess_user(mock_odata_client, tier_config, "employee1")

        assert response.result["required_tier"]["name"] == "Universal"
        assert response.result["required_tier"]["monthly_cost"] == 5.8

    async def test_assess_user_none_tier_returns_none(self, mock_odata_client, tier_config):
        """User 'svcaccount' has only SYSTEMUSER (None tier)."""
        response = await assess_user(mock_odata_client, tier_config, "svcaccount")

        assert response.result["required_tier"]["name"] == "None"
        assert response.result["required_tier"]["monthly_cost"] == 0.0

    async def test_assess_user_no_roles_returns_none_tier(self, mock_odata_client, tier_config):
        """A user with no role assignments should get None tier."""
        response = await assess_user(mock_odata_client, tier_config, "noroles")

        assert response.result["required_tier"]["name"] == "None"
        assert response.result["role_count"] == 0

    async def test_assess_user_driving_role_is_set(self, mock_odata_client, tier_config):
        """The first role matching the required tier should be flagged as driving."""
        response = await assess_user(mock_odata_client, tier_config, "admin")

        driving_roles = [r for r in response.result["roles"] if r["is_driving"] is True]
        assert len(driving_roles) == 1
        assert driving_roles[0]["role_identifier"] == "SYSADMIN"

    async def test_assess_user_roles_contain_licence_tier_info(
        self, mock_odata_client, tier_config
    ):
        """Each role in the result should carry licence_tier metadata."""
        response = await assess_user(mock_odata_client, tier_config, "jsmith")

        for role in response.result["roles"]:
            assert "licence_tier" in role
            assert role["licence_tier"] is not None
            assert "name" in role["licence_tier"]
            assert "monthly_cost" in role["licence_tier"]

    async def test_assess_user_metadata_has_environment(self, mock_odata_client, tier_config):
        """Response metadata should contain the client environment."""
        response = await assess_user(mock_odata_client, tier_config, "admin")

        assert response.metadata.environment == "test.operations.dynamics.com"

    async def test_assess_user_multiuser_enterprise_highest(self, mock_odata_client, tier_config):
        """User 'multiuser' has Enterprise + Activity + Universal — Enterprise wins."""
        response = await assess_user(mock_odata_client, tier_config, "multiuser")

        assert response.result["required_tier"]["name"] == "Enterprise"
        assert response.result["role_count"] == 3

    async def test_assess_user_display_name_populated(self, mock_odata_client, tier_config):
        """The required_tier should include a human-readable display_name."""
        response = await assess_user(mock_odata_client, tier_config, "admin")

        display = response.result["required_tier"]["display_name"]
        assert isinstance(display, str)
        assert len(display) > 0


# ---------------------------------------------------------------------------
# assess_all_users
# ---------------------------------------------------------------------------


class TestAssessAllUsers:
    """Tests for the assess_all_users tool."""

    async def test_assess_all_users_returns_all_enabled_users(self, mock_odata_client, tier_config):
        """Should return one assessment per enabled system user."""
        response = await assess_all_users(mock_odata_client, tier_config)

        assert response.result["total_users"] == 10
        assert len(response.result["assessments"]) == 10

    async def test_assess_all_users_assessments_have_required_fields(
        self, mock_odata_client, tier_config
    ):
        """Each assessment should contain user_id, required_tier, role_count, etc."""
        response = await assess_all_users(mock_odata_client, tier_config)

        for assessment in response.result["assessments"]:
            assert "user_id" in assessment
            assert "user_name" in assessment
            assert "required_tier" in assessment
            assert "role_count" in assessment
            assert "roles" in assessment
            assert "driving_role" in assessment

    async def test_assess_all_users_noroles_user_gets_none_tier(
        self, mock_odata_client, tier_config
    ):
        """User 'noroles' exists in system_users but has no assignments."""
        response = await assess_all_users(mock_odata_client, tier_config)

        noroles = [a for a in response.result["assessments"] if a["user_id"] == "noroles"]
        assert len(noroles) == 1
        assert noroles[0]["required_tier"]["name"] == "None"
        assert noroles[0]["role_count"] == 0

    async def test_assess_all_users_metadata_has_environment(self, mock_odata_client, tier_config):
        """Response metadata should contain the client environment."""
        response = await assess_all_users(mock_odata_client, tier_config)

        assert response.metadata.environment == "test.operations.dynamics.com"

    async def test_assess_all_users_no_warnings_for_known_tiers(
        self, mock_odata_client, tier_config
    ):
        """All fixture roles have a UserLicenseType, so no warnings should occur."""
        response = await assess_all_users(mock_odata_client, tier_config)

        assert response.warnings == []


# ---------------------------------------------------------------------------
# EC-002: custom roles treated identically to standard roles
# ---------------------------------------------------------------------------


class TestAssessCustomRole:
    """Tests covering EC-002: custom roles classified by UserLicenseType regardless of origin."""

    async def test_assess_custom_role_treats_user_license_type_as_authoritative(self, tier_config):
        """Custom role (CUSTOM_ prefix) with UserLicenseType=Enterprise is classified
        identically to a standard Enterprise role (covers spec EC-002)."""
        custom_roles = [
            {
                "SecurityRoleIdentifier": "CUSTOM_ENTERPRISEAPPROVER",
                "SecurityRoleName": "Custom Enterprise Approver",
                "UserLicenseType": "Enterprise",
            }
        ]
        custom_assignments = [
            {
                "UserId": "customuser",
                "SecurityRoleIdentifier": "CUSTOM_ENTERPRISEAPPROVER",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            }
        ]

        async def _query(entity: str, filter_expr: str = "", **kwargs):
            if "SecurityRoles" in entity:
                return list(custom_roles)
            if "UserRoleAssociations" in entity or "SecurityUserRole" in entity:
                if filter_expr and "UserId eq 'customuser'" in filter_expr:
                    return [a for a in custom_assignments if a["UserId"] == "customuser"]
                return list(custom_assignments)
            return []

        client = MagicMock()
        client.query = AsyncMock(side_effect=_query)
        client.environment = "test.operations.dynamics.com"

        response = await assess_user(client, tier_config, "customuser")

        assert response.result["required_tier"]["name"] == "Enterprise"
        assert response.result["required_tier"]["monthly_cost"] == 135.7
        assert response.result["role_count"] == 1
        assert response.result["driving_role"] == "CUSTOM_ENTERPRISEAPPROVER"
        assert response.warnings == []


# ---------------------------------------------------------------------------
# Driving role tiebreaker (T008)
# ---------------------------------------------------------------------------


def _make_tiebreaker_client(
    roles: list[dict],
    assignments: list[dict],
    duties: list[dict],
    users: list[dict] | None = None,
):
    """Build a mock OData client with custom roles, assignments, duties, and users."""

    async def _query(entity: str, filter_expr: str = "", **kwargs):
        if "SecurityRoles" in entity:
            return list(roles)
        if "UserRoleAssociations" in entity or "SecurityUserRole" in entity:
            if filter_expr and "UserId eq" in filter_expr:
                # Extract user id from filter
                start = filter_expr.find("'") + 1
                end = filter_expr.find("'", start)
                uid = filter_expr[start:end]
                return [a for a in assignments if a["UserId"] == uid]
            return list(assignments)
        if "SecurityRoleDuties" in entity or "SecurityDuties" in entity:
            return list(duties)
        if "SystemUsers" in entity:
            return list(users or [])
        return []

    client = MagicMock()
    client.query = AsyncMock(side_effect=_query)
    client.environment = "test.operations.dynamics.com"
    return client


class TestDrivingRoleTiebreaker:
    """Tests for the driving_role duty-count tiebreaker logic (T005/T006)."""

    @pytest.mark.asyncio
    async def test_assess_all_users_driving_role_picks_highest_duty_count(self, tier_config):
        """Two roles at same tier -- role with more duties is picked."""
        roles = [
            {
                "SecurityRoleIdentifier": "ROLE_A",
                "SecurityRoleName": "Alpha Role",
                "UserLicenseType": "Enterprise",
            },
            {
                "SecurityRoleIdentifier": "ROLE_B",
                "SecurityRoleName": "Beta Role",
                "UserLicenseType": "Enterprise",
            },
        ]
        assignments = [
            {
                "UserId": "user1",
                "SecurityRoleIdentifier": "ROLE_A",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
            {
                "UserId": "user1",
                "SecurityRoleIdentifier": "ROLE_B",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
        ]
        # ROLE_B has more duties than ROLE_A
        duties = [
            {"SecurityRoleIdentifier": "ROLE_A", "SecurityDutyIdentifier": "DUTY1"},
            {"SecurityRoleIdentifier": "ROLE_B", "SecurityDutyIdentifier": "DUTY1"},
            {"SecurityRoleIdentifier": "ROLE_B", "SecurityDutyIdentifier": "DUTY2"},
            {"SecurityRoleIdentifier": "ROLE_B", "SecurityDutyIdentifier": "DUTY3"},
        ]
        users = [
            {
                "UserID": "user1",
                "UserName": "user1",
                "PersonName": "User One",
                "Email": "u1@test.com",
                "Enabled": True,
            },
        ]
        client = _make_tiebreaker_client(roles, assignments, duties, users)

        response = await assess_all_users(client, tier_config)
        assessment = response.result["assessments"][0]

        assert assessment["driving_role"] == "ROLE_B"
        driving = [r for r in assessment["roles"] if r["is_driving"]]
        assert len(driving) == 1
        assert driving[0]["role_identifier"] == "ROLE_B"

    @pytest.mark.asyncio
    async def test_assess_all_users_driving_role_tied_duties_falls_back_alphabetical(
        self, tier_config
    ):
        """Same duty count -- alphabetically first role name wins."""
        roles = [
            {
                "SecurityRoleIdentifier": "ROLE_Z",
                "SecurityRoleName": "Zebra Role",
                "UserLicenseType": "Enterprise",
            },
            {
                "SecurityRoleIdentifier": "ROLE_A",
                "SecurityRoleName": "Alpha Role",
                "UserLicenseType": "Enterprise",
            },
        ]
        assignments = [
            {
                "UserId": "user1",
                "SecurityRoleIdentifier": "ROLE_Z",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
            {
                "UserId": "user1",
                "SecurityRoleIdentifier": "ROLE_A",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
        ]
        duties = [
            {"SecurityRoleIdentifier": "ROLE_Z", "SecurityDutyIdentifier": "DUTY1"},
            {"SecurityRoleIdentifier": "ROLE_A", "SecurityDutyIdentifier": "DUTY2"},
        ]
        users = [
            {
                "UserID": "user1",
                "UserName": "user1",
                "PersonName": "User One",
                "Email": "u1@test.com",
                "Enabled": True,
            },
        ]
        client = _make_tiebreaker_client(roles, assignments, duties, users)

        response = await assess_all_users(client, tier_config)
        assessment = response.result["assessments"][0]

        # "Alpha Role" is alphabetically before "Zebra Role"
        assert assessment["driving_role"] == "ROLE_A"

    @pytest.mark.asyncio
    async def test_assess_user_driving_role_picks_highest_duty_count(self, tier_config):
        """Single-user assess: role with more duties wins."""
        roles = [
            {
                "SecurityRoleIdentifier": "ROLE_X",
                "SecurityRoleName": "X-Ray Role",
                "UserLicenseType": "Activity",
            },
            {
                "SecurityRoleIdentifier": "ROLE_Y",
                "SecurityRoleName": "Yankee Role",
                "UserLicenseType": "Activity",
            },
        ]
        assignments = [
            {
                "UserId": "testuser",
                "SecurityRoleIdentifier": "ROLE_X",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
            {
                "UserId": "testuser",
                "SecurityRoleIdentifier": "ROLE_Y",
                "AssignmentStatus": "Active",
                "AssignmentMode": "Direct",
            },
        ]
        # ROLE_X has 3 duties, ROLE_Y has 1
        duties = [
            {"SecurityRoleIdentifier": "ROLE_X", "SecurityDutyIdentifier": "D1"},
            {"SecurityRoleIdentifier": "ROLE_X", "SecurityDutyIdentifier": "D2"},
            {"SecurityRoleIdentifier": "ROLE_X", "SecurityDutyIdentifier": "D3"},
            {"SecurityRoleIdentifier": "ROLE_Y", "SecurityDutyIdentifier": "D4"},
        ]
        client = _make_tiebreaker_client(roles, assignments, duties)

        response = await assess_user(client, tier_config, "testuser")

        assert response.result["driving_role"] == "ROLE_X"

    @pytest.mark.asyncio
    async def test_assess_all_users_zero_roles_driving_role_null(self, tier_config):
        """User with no roles has driving_role=None."""
        roles = [
            {
                "SecurityRoleIdentifier": "SOMEROLE",
                "SecurityRoleName": "Some Role",
                "UserLicenseType": "Enterprise",
            },
        ]
        assignments: list[dict] = []
        duties: list[dict] = []
        users = [
            {
                "UserID": "lonely",
                "UserName": "lonely",
                "PersonName": "Lonely User",
                "Email": "l@test.com",
                "Enabled": True,
            },
        ]
        client = _make_tiebreaker_client(roles, assignments, duties, users)

        response = await assess_all_users(client, tier_config)
        assessment = response.result["assessments"][0]

        assert assessment["driving_role"] is None
        assert assessment["role_count"] == 0


# ---------------------------------------------------------------------------
# Filtered assessment (T010–T014)
# ---------------------------------------------------------------------------


class TestAssessAllUsersFiltering:
    """Tests for tier_filter, min_role_count, and include_roles parameters."""

    async def test_assess_all_users_tier_filter_returns_matching_tier(
        self, mock_odata_client, tier_config
    ):
        """Filter by 'Enterprise' returns only Enterprise-tier users."""
        response = await assess_all_users(mock_odata_client, tier_config, tier_filter="Enterprise")

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert assessment["required_tier"]["name"] == "Enterprise"

    async def test_assess_all_users_min_role_count_filters_by_threshold(
        self, mock_odata_client, tier_config
    ):
        """min_role_count=3 returns only users with 3+ roles."""
        response = await assess_all_users(mock_odata_client, tier_config, min_role_count=3)

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert assessment["role_count"] >= 3

    async def test_assess_all_users_combined_filters_are_and_logic(
        self, mock_odata_client, tier_config
    ):
        """tier_filter + min_role_count combined: only users matching both."""
        response = await assess_all_users(
            mock_odata_client,
            tier_config,
            tier_filter="Enterprise",
            min_role_count=2,
        )

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert assessment["required_tier"]["name"] == "Enterprise"
            assert assessment["role_count"] >= 2

    async def test_assess_all_users_invalid_tier_filter_returns_empty_with_warning(
        self, mock_odata_client, tier_config
    ):
        """Invalid tier name returns empty assessments with a warning listing valid names."""
        response = await assess_all_users(mock_odata_client, tier_config, tier_filter="InvalidTier")

        assert response.result["total_users"] == 0
        assert response.result["assessments"] == []
        assert len(response.warnings) >= 1
        warning = response.warnings[-1]
        assert "Invalid tier_filter 'InvalidTier'" in warning
        assert "Valid tier names:" in warning

    async def test_assess_all_users_include_roles_false_omits_roles_key(
        self, mock_odata_client, tier_config
    ):
        """When include_roles=False, the 'roles' key is absent from each assessment."""
        response = await assess_all_users(mock_odata_client, tier_config, include_roles=False)

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert "roles" not in assessment

    async def test_assess_all_users_include_roles_true_includes_roles_key(
        self, mock_odata_client, tier_config
    ):
        """When include_roles=True (default), the 'roles' key is present."""
        response = await assess_all_users(mock_odata_client, tier_config, include_roles=True)

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert "roles" in assessment

    async def test_assess_all_users_tier_filter_activity_returns_only_activity(
        self, mock_odata_client, tier_config
    ):
        """Filter by 'Activity' returns only Activity-tier users."""
        response = await assess_all_users(mock_odata_client, tier_config, tier_filter="Activity")

        assert response.result["total_users"] > 0
        for assessment in response.result["assessments"]:
            assert assessment["required_tier"]["name"] == "Activity"

    async def test_assess_all_users_high_min_role_count_returns_empty(
        self, mock_odata_client, tier_config
    ):
        """min_role_count=100 returns empty when no user has that many roles."""
        response = await assess_all_users(mock_odata_client, tier_config, min_role_count=100)

        assert response.result["total_users"] == 0
        assert response.result["assessments"] == []

    async def test_assess_all_users_user_id_overrides_filters(self, mock_odata_client, tier_config):
        """FR-007: When user_id is set, filters are ignored (server-level concern).

        assess_user() does not accept filter params, so calling it with a
        user_id inherently ignores filters. This test verifies that
        assess_user() returns the single user regardless of what tier they are,
        confirming the server-level override design.
        """
        # "warehouse1" is Activity-tier; if filters were applied, an
        # Enterprise tier_filter would exclude them. But assess_user returns them.
        response = await assess_user(mock_odata_client, tier_config, "warehouse1")

        assert response.result["user_id"] == "warehouse1"
        assert response.result["required_tier"]["name"] == "Activity"
