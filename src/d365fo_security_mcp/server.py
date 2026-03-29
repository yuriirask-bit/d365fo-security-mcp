from __future__ import annotations

import json
import logging
from typing import Any

from fastmcp import FastMCP

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.models.licence import LicenceTierConfig
from d365fo_security_mcp.models.sod import SodRuleset
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.assess import assess_all_users, assess_user
from d365fo_security_mcp.tools.drilldown import get_role_licence_details
from d365fo_security_mcp.tools.licence_source import (
    get_security_server_config as _get_security_server_config,
)
from d365fo_security_mcp.tools.licence_source import (
    validate_licence_source as _validate_licence_source,
)
from d365fo_security_mcp.tools.over_licensed import detect_over_licensed
from d365fo_security_mcp.tools.providers import create_provider
from d365fo_security_mcp.tools.providers.base import LicenceSourceProvider
from d365fo_security_mcp.tools.sod.access_review import (
    run_user_access_review as _run_user_access_review,
)
from d365fo_security_mcp.tools.sod.assignments import (
    get_all_user_role_assignments as _get_all_user_role_assignments,
)
from d365fo_security_mcp.tools.sod.change_log import (
    get_security_change_log as _get_security_change_log,
)
from d365fo_security_mcp.tools.sod.dormant import (
    find_dormant_privileged_accounts as _find_dormant_privileged_accounts,
)
from d365fo_security_mcp.tools.sod.health_score import (
    get_security_health_score as _get_security_health_score,
)
from d365fo_security_mcp.tools.sod.high_risk import (
    get_high_risk_users as _get_high_risk_users,
)
from d365fo_security_mcp.tools.sod.matrix import (
    get_sod_conflict_matrix as _get_sod_conflict_matrix,
)
from d365fo_security_mcp.tools.sod.org_map import (
    get_org_security_map as _get_org_security_map,
)
from d365fo_security_mcp.tools.sod.profile import (
    get_user_security_profile as _get_user_security_profile,
)
from d365fo_security_mcp.tools.sod.role_tree import (
    get_role_duty_tree as _get_role_duty_tree,
)
from d365fo_security_mcp.tools.sod.ruleset import load_ruleset
from d365fo_security_mcp.tools.sod.violations import (
    detect_sod_violations as _detect_sod_violations,
)
from d365fo_security_mcp.tools.summary import get_licence_summary
from d365fo_security_mcp.tools.under_licensed import detect_under_licensed
from d365fo_security_mcp.tools.what_if import what_if_analysis

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "D365 F&O Security MCP Server",
    instructions=(
        "Security & licence intelligence tools for Microsoft Dynamics 365 "
        "Finance & Operations. Query security roles, analyse licence "
        "requirements, detect over/under-licensed users, and simulate "
        "role change impact on licensing costs. Use get_security_server_config "
        "to inspect the server's configuration, environment connectivity, "
        "and which tools are available. Use validate_licence_source to test "
        "licence source connectivity before running detection tools."
    ),
)

# Module-level state, initialized lazily by init_server()
_client: ODataClient | None = None
_tier_config: LicenceTierConfig | None = None
_server_config: ServerConfig | None = None
_provider: LicenceSourceProvider | None = None
_profile: D365Profile | None = None
_sod_ruleset: SodRuleset | None = None
_sod_ruleset_warnings: list[str] = []


def init_server() -> None:
    """Initialize module-level state from environment configuration."""
    global _client, _tier_config, _server_config, _provider, _profile
    global _sod_ruleset, _sod_ruleset_warnings

    profile = D365Profile()  # type: ignore[call-arg]  # reads from env
    _profile = profile
    _server_config = ServerConfig()  # type: ignore[call-arg]
    _client = ODataClient(profile)
    _tier_config = LicenceTierConfig(currency=_server_config.currency)

    provider_kwargs: dict[str, Any] = {}
    if _server_config.licence_source == "file":
        provider_kwargs["file_path"] = _server_config.licence_file_path
    elif _server_config.licence_source == "graph":
        provider_kwargs["tenant_id"] = profile.tenant_id
        provider_kwargs["client_id"] = profile.client_id
        provider_kwargs["client_secret"] = profile.client_secret
        provider_kwargs["graph_scope"] = _server_config.graph_scope
    _provider = create_provider(_server_config.licence_source, **provider_kwargs)

    # Load SoD ruleset (optional — server works without it but SoD tools are unavailable)
    if _server_config.sod_rules_file:
        try:
            _sod_ruleset, _sod_ruleset_warnings = load_ruleset(_server_config.sod_rules_file)
        except (FileNotFoundError, ValueError) as exc:
            logger.warning("Failed to load SoD ruleset: %s", exc)
            _sod_ruleset = None
            _sod_ruleset_warnings = [str(exc)]
    else:
        _sod_ruleset = None
        _sod_ruleset_warnings = []

    logger.info("D365 F&O Security MCP Server initialized.")


def _get_client() -> ODataClient:
    if _client is None:
        init_server()
    assert _client is not None
    return _client


def _get_tier_config() -> LicenceTierConfig:
    if _tier_config is None:
        init_server()
    assert _tier_config is not None
    return _tier_config


def _get_provider() -> LicenceSourceProvider:
    if _provider is None:
        init_server()
    assert _provider is not None
    return _provider


def _get_sod_ruleset() -> SodRuleset | None:
    if _sod_ruleset is None and _server_config is None:
        init_server()
    return _sod_ruleset


def _get_sod_warnings() -> list[str]:
    return list(_sod_ruleset_warnings)


def _get_server_config() -> ServerConfig:
    if _server_config is None:
        init_server()
    assert _server_config is not None
    return _server_config


def _get_profile() -> D365Profile:
    if _profile is None:
        init_server()
    assert _profile is not None
    return _profile


@mcp.tool()
async def assess_user_licence_requirements(
    user_id: str = "",
    redact_pii: bool = False,
    tier_filter: str = "",
    min_role_count: int = 0,
    include_roles: bool = False,
) -> str:
    """Assess licence requirements for D365 F&O users based on their security roles.

    Calculates the minimum required licence tier for each user by analysing
    their assigned security roles. Returns the tier, cost, and driving role.

    Args:
        user_id: Specific user ID to assess. Leave empty to assess all users.
        redact_pii: If true, hash user names and emails in output.
        tier_filter: Filter by licence tier name (e.g. "Enterprise", "Activity").
            Empty string means no filter. Invalid values return empty results
            with a warning listing valid tier names.
        min_role_count: Minimum number of roles a user must have to be included.
            0 means no filter. Example: 10 returns only users with 10+ roles.
        include_roles: If true, include full role arrays in response. If false
            (default), return compact format without role details.
    """
    client = _get_client()
    tier_config = _get_tier_config()

    if user_id:
        result = await assess_user(
            user_id=user_id,
            client=client,
            tier_config=tier_config,
            redact_pii=redact_pii,
        )
    else:
        result = await assess_all_users(
            client=client,
            tier_config=tier_config,
            redact_pii=redact_pii,
            tier_filter=tier_filter,
            min_role_count=min_role_count,
            include_roles=include_roles,
        )

    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def detect_over_licensed_users(redact_pii: bool = False) -> str:
    """Detect users whose assigned licence exceeds what their security roles require.

    Compares each user's calculated minimum licence requirement against their
    assigned licence to find cost-saving opportunities.

    Args:
        redact_pii: If true, hash user names and emails in output.
    """
    client = _get_client()
    tier_config = _get_tier_config()
    provider = _get_provider()
    config = _get_server_config()
    result = await detect_over_licensed(
        client,
        tier_config,
        provider,
        redact_pii=redact_pii,
        batch_size=config.batch_size,
        stale_threshold_days=config.stale_threshold_days,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def detect_under_licensed_users(redact_pii: bool = False) -> str:
    """Detect users whose roles require a higher licence than currently assigned.

    Identifies compliance risks under Microsoft's licence enforcement policy.
    Requires an external licence source (graph, ppac, or file).

    Args:
        redact_pii: If true, hash user names and emails in output.
    """
    client = _get_client()
    tier_config = _get_tier_config()
    provider = _get_provider()
    config = _get_server_config()
    result = await detect_under_licensed(
        client,
        tier_config,
        provider,
        redact_pii=redact_pii,
        batch_size=config.batch_size,
        stale_threshold_days=config.stale_threshold_days,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def what_if_role_change(
    user_id: str,
    add_roles: str = "",
    remove_roles: str = "",
    redact_pii: bool = False,
) -> str:
    """Simulate the licence impact of adding or removing roles from a user.

    Shows the projected licence tier and cost delta before making changes
    in D365. No changes are made to the environment.

    Args:
        user_id: The D365 user ID to analyse.
        add_roles: Comma-separated role identifiers to add.
        remove_roles: Comma-separated role identifiers to remove.
        redact_pii: If true, hash user ID in output.
    """
    client = _get_client()
    tier_config = _get_tier_config()
    add_list = [r.strip() for r in add_roles.split(",") if r.strip()] if add_roles else []
    remove_list = [r.strip() for r in remove_roles.split(",") if r.strip()] if remove_roles else []
    result = await what_if_analysis(
        client,
        tier_config,
        user_id,
        add_roles=add_list,
        remove_roles=remove_list,
        ruleset=_get_sod_ruleset(),
        redact_pii=redact_pii,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_licence_summary_report(redact_pii: bool = False) -> str:
    """Get an aggregate overview of licence consumption across the environment.

    Returns counts of users at each licence tier, total estimated cost,
    over/under-licensed counts, and savings opportunity.

    Args:
        redact_pii: If true, hash user names and emails in output.
    """
    client = _get_client()
    tier_config = _get_tier_config()
    provider = _get_provider()
    config = _get_server_config()
    result = await get_licence_summary(
        client,
        tier_config,
        provider,
        redact_pii=redact_pii,
        batch_size=config.batch_size,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_role_licence_breakdown(
    role_identifier: str,
    summary_only: bool = False,
) -> str:
    """Explain why a security role requires its licence tier.

    Traverses the role's duties and privileges to identify which specific
    components drive the licence classification.

    Args:
        role_identifier: The D365 security role identifier (e.g. 'LEDGERACCOUNTANT').
        summary_only: If true, return duties only without the full privileges array.
            Reduces response size for roles with thousands of privileges.
            privilege_count is still included as a scalar.
    """
    client = _get_client()
    tier_config = _get_tier_config()
    result = await get_role_licence_details(
        client, tier_config, role_identifier, summary_only=summary_only
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_security_server_config() -> str:
    """Inspect the server's configuration, environment, and capabilities.

    Returns the server version, D365 environment info (URL, version,
    connectivity), licence source configuration with available options,
    a capabilities map showing which tools are functional, and a
    limitations array explaining any degraded functionality.
    """
    client = _get_client()
    config = _get_server_config()
    provider = _get_provider()
    profile = _get_profile()
    result = await _get_security_server_config(client, config, provider, profile)
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def validate_licence_source(source: str = "") -> str:
    """Test connectivity and data availability for a licence source.

    Validates the currently configured licence source, or a specific source
    if the source parameter is provided. Returns a structured validation
    breakdown including authentication status, permissions, data statistics,
    and actionable remediation guidance on failure.

    Args:
        source: Specific source to validate (e.g. "graph", "file").
            Leave empty to validate the currently configured source.
    """
    provider = _get_provider()
    config = _get_server_config()
    result = await _validate_licence_source(provider, config, source=source)
    return json.dumps(result.model_dump(), default=str)


# ---------------------------------------------------------------------------
# SoD Conflict Detection Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def detect_sod_violations(
    user_id: str = "",
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Run the configured SoD conflict ruleset against all users or a specific user.

    Detects segregation of duties violations by comparing each user's
    effective duty set against all conflict rules. Returns violations
    grouped by user with matched duties, granting roles, and risk levels.

    Args:
        user_id: Scope to a single user. Leave empty to scan all enabled users.
        redact_pii: If true, hash user names in output.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    result = await _detect_sod_violations(
        client,
        ruleset,
        user_id=user_id,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_sod_conflict_matrix(
    category: str = "",
) -> str:
    """Return the configured SoD conflict ruleset for inspection.

    Shows all conflict rules with their duty groups, risk levels, and
    descriptions. Supports filtering by category.

    Args:
        category: Filter to a specific category (e.g. "accounts_payable").
            Leave empty to return all rules.
    """
    ruleset = _get_sod_ruleset()
    result = await _get_sod_conflict_matrix(ruleset, category=category)
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_user_security_profile(
    user_id: str,
    redact_pii: bool = False,
    summary_only: bool = False,
) -> str:
    """Return a user's complete security profile with SoD violations.

    Builds a hierarchical view: roles, duties per role, privileges per
    duty, plus any SoD violations detected for the user.

    Args:
        user_id: The D365 user ID to profile.
        redact_pii: If true, hash user name and email in output.
        summary_only: If true, skip the expensive privileges query and return
            compact role entries with duty_count and privilege_count instead
            of full arrays. SoD violations are always included.
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    result = await _get_user_security_profile(
        client, ruleset, user_id=user_id, redact_pii=redact_pii, summary_only=summary_only
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_high_risk_users(
    top: int = 0,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Rank users by SoD violation count and severity.

    Runs a full SoD scan and returns users sorted by risk score
    (Critical=3, High=2, Medium=1 weighting). Use top to limit results.

    Args:
        top: Limit to top N users. 0 = all users with violations.
        redact_pii: If true, hash user names in output.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    result = await _get_high_risk_users(
        client,
        ruleset,
        top=top,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_role_duty_tree(
    role: str,
    include_sod_flags: bool = False,
) -> str:
    """Return the full duty/privilege hierarchy for a security role.

    Includes sub-role resolution. When include_sod_flags is true, each
    duty is annotated with whether it participates in any SoD conflict rule.

    Args:
        role: The D365 security role identifier to inspect.
        include_sod_flags: Annotate duties with SoD conflict participation.
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    result = await _get_role_duty_tree(
        client, ruleset, role=role, include_sod_flags=include_sod_flags
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_all_user_role_assignments(
    active_only: bool = False,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Return the complete user-role assignment matrix.

    Lists every enabled user with their assigned roles, status, and
    assignment mode. Use active_only to exclude expired/suspended
    assignments.

    Args:
        active_only: If true, exclude expired and suspended assignments.
        redact_pii: Hash user names in output.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    result = await _get_all_user_role_assignments(
        client,
        active_only=active_only,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_org_security_map(
    user_id: str = "",
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Map users to their organisation-scoped role assignments.

    Shows which users can operate in which legal entities. Users with
    only globally-scoped roles are included and marked accordingly.

    Args:
        user_id: Scope to a single user. Leave empty for all users.
        redact_pii: Hash user names in output.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    result = await _get_org_security_map(
        client,
        user_id=user_id,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_security_change_log(
    days: int = 30,
    user_id: str = "",
    redact_pii: bool = False,
) -> str:
    """Retrieve role assignment changes over a date range.

    Queries App Insights customEvents emitted by the
    SMCPSecurityRoleEventHandler X++ class. Requires App Insights
    configured and the X++ event handler deployed in D365.

    Args:
        days: Look back N days from today.
        user_id: Filter to a specific user. Leave empty for all changes.
        redact_pii: Hash user names in output.
    """
    client = _get_client()
    profile = _get_profile()
    config = _get_server_config()
    result = await _get_security_change_log(
        client,
        days=days,
        user_id=user_id,
        redact_pii=redact_pii,
        tenant_id=profile.tenant_id,
        client_id=profile.client_id,
        client_secret=profile.client_secret,
        app_insights_connection_string=config.app_insights_connection_string,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def find_dormant_privileged_accounts(
    days: int = 90,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Find privileged users who haven't logged in within the threshold.

    Checks App Insights pageViews, Database Logging, and Microsoft Graph
    sign-in activity. Privileged roles are defined in the SoD ruleset file.

    Args:
        days: Dormancy threshold in days.
        redact_pii: If true, hash user names in output.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    profile = _get_profile()
    config = _get_server_config()
    result = await _find_dormant_privileged_accounts(
        client,
        ruleset,
        days=days,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
        tenant_id=profile.tenant_id,
        client_id=profile.client_id,
        client_secret=profile.client_secret,
        graph_scope=config.graph_scope,
        app_insights_connection_string=config.app_insights_connection_string,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def run_user_access_review(
    include_disabled: bool = False,
    sod_only: bool = False,
    redact_pii: bool = False,
    exclude_service_accounts: bool = True,
) -> str:
    """Produce a compliance-ready user access review list.

    Lists every user with their enabled status, role assignments, last
    login date, and SoD violation flags.

    Args:
        include_disabled: Include disabled user accounts.
        sod_only: Only return users with SoD violations.
        redact_pii: If true, hash user names and emails.
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    profile = _get_profile()
    config = _get_server_config()
    result = await _run_user_access_review(
        client,
        ruleset,
        include_disabled=include_disabled,
        sod_only=sod_only,
        redact_pii=redact_pii,
        exclude_service_accounts=exclude_service_accounts,
        tenant_id=profile.tenant_id,
        client_id=profile.client_id,
        client_secret=profile.client_secret,
        graph_scope=config.graph_scope,
        app_insights_connection_string=config.app_insights_connection_string,
    )
    return json.dumps(result.model_dump(), default=str)


@mcp.tool()
async def get_security_health_score(
    exclude_service_accounts: bool = True,
) -> str:
    """Calculate aggregate security posture score (0–100).

    Returns an overall score with dimensional breakdown across SoD
    compliance, dormant accounts, role hygiene, and data completeness.
    Includes plain-English recommendations.

    Args:
        exclude_service_accounts: Exclude non-native accounts (different Provider than Admin).
    """
    client = _get_client()
    ruleset = _get_sod_ruleset()
    profile = _get_profile()
    config = _get_server_config()
    result = await _get_security_health_score(
        client,
        ruleset,
        exclude_service_accounts=exclude_service_accounts,
        tenant_id=profile.tenant_id,
        client_id=profile.client_id,
        client_secret=profile.client_secret,
        graph_scope=config.graph_scope,
        app_insights_connection_string=config.app_insights_connection_string,
    )
    return json.dumps(result.model_dump(), default=str)
