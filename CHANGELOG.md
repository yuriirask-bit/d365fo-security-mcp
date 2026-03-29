# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `what_if_role_change` now projects SoD conflicts alongside licence impact, showing which conflicts would be introduced or resolved by proposed role changes
- `summary_only` parameter on `get_user_security_profile` — returns an agent-friendly compact response with counts and top-level roles, omitting the full duty/privilege hierarchy
- `exclude_service_accounts` parameter on most user-scanning tools — Provider-based native detection filters out service and system accounts from results

### Fixed

- `redact_pii` parameter now supported on `get_all_user_role_assignments`, `get_org_security_map`, and `get_security_change_log` (previously missing)

### Previously Added

- **SoD Conflict Detection** — 11 new MCP tools for segregation of duties analysis and security posture monitoring:
  - `detect_sod_violations` — run SoD conflict rules against all users or a specific user with ANY-to-ANY matching, sub-role resolution, and duty deduplication
  - `get_sod_conflict_matrix` — inspect the configured SoD conflict ruleset with optional category filtering
  - `get_user_security_profile` — full role → duty → privilege hierarchy for a user with inline SoD violations
  - `get_high_risk_users` — rank users by SoD violation count and severity (Critical=3, High=2, Medium=1)
  - `get_role_duty_tree` — role hierarchy with sub-role resolution and optional SoD conflict annotations per duty
  - `get_all_user_role_assignments` — complete user-role assignment matrix with status filtering
  - `get_org_security_map` — legal entity scoped access map showing which users can operate in which organisations
  - `get_security_change_log` — role assignment changes via DatabaseLogs entity (requires D365 Database Logging)
  - `find_dormant_privileged_accounts` — dual-source login data (D365 + Microsoft Graph) with configurable dormancy threshold
  - `run_user_access_review` — quarterly compliance access review list with SoD violation flags
  - `get_security_health_score` — aggregate 0–100 security posture score across 4 dimensions with plain-English recommendations
- Fully data-driven SoD ruleset loaded from external JSON file (`SOD_RULES_FILE` env var) — not embedded in codebase
- Example SoD ruleset in `examples/sod-rules-sample.json` (5 rules across 4 categories)
- SoD ruleset file format documentation in `docs/sod-ruleset-format.md`
- `SOD_RULES_FILE` configuration variable for specifying the SoD ruleset path
- Privileged role definition: curated list in ruleset file with fallback to SoD-participating roles + admin roles
- `get_security_server_config` MCP tool — returns server version, D365 environment info (URL, version, connectivity), licence source configuration with available sources, capabilities map showing which tools are functional, and limitations array with human-readable explanations
- `validate_licence_source` MCP tool — tests connectivity and data availability for a licence source with structured validation breakdown (authentication/permissions/data status), row-level file error details, licence tiers found, and actionable remediation guidance; optional `source` parameter for pre-validation
- Compact `user_list` array in `get_licence_summary_report` response — each entry contains user_id, user_name, required_tier (display name), driving_role, and role_count, sorted by tier priority descending
- `tier_filter`, `min_role_count`, and `include_roles` parameters on `assess_user_licence_requirements` — enables filtered queries (e.g., "Enterprise-tier users only") and compact response mode without full role arrays
- `BaseLicenceSourceProvider` abstract base class with default `validate()` and `last_sync_time` for all licence source providers
- `valid_tier_names` property on `LicenceTierConfig` returning all 13 tier names
- `stale_threshold_days` configuration (env var `STALE_THRESHOLD_DAYS`, default 7) for licence data freshness checking
- Projection mode warning on `detect_over_licensed_users` when no licence source is configured — explains limitation and references `get_security_server_config` for setup guidance
- Stale data warnings on `detect_over_licensed_users` and `detect_under_licensed_users` when licence source data exceeds the configured freshness threshold
- D365 application version detection in `get_security_server_config` — extracts version from environment root HTML page with `D365FO_VERSION` env var override for manual configuration
- `summary_only` parameter on `get_role_licence_breakdown` — omits the privileges array (which can contain thousands of entries) while retaining `privilege_count` as a scalar, keeping responses within AI context limits

### Changed

- Driving role tiebreaker in `assess_user` and `assess_all_users` — when multiple roles share the highest tier, the role with the most duties is selected (previously: first match). Duty query is deferred until tiebreaker is needed (2+ candidates) to maintain <2s p95 for single-user assessments
- All four licence source providers (AssessOnlyProvider, FileProvider, GraphProvider, PpacProvider) now inherit from `BaseLicenceSourceProvider`

## [0.1.0] - 2026-03-23

### Added

- Initial project scaffolding
- `assess_user_licence_requirements` MCP tool — per-user licence tier calculation from D365 security roles (US1)
- `detect_over_licensed_users` MCP tool — identify users whose assigned licence exceeds their role requirements, with per-user and aggregate savings (US2)
- `detect_under_licensed_users` MCP tool — identify compliance risks where assigned licence is below role requirements (US3)
- `what_if_role_change` MCP tool — simulate add/remove role changes and project licence tier and cost delta before applying them (US4)
- `get_licence_summary_report` MCP tool — aggregate licence consumption overview with tier breakdown, total costs, and savings opportunity (US5)
- `get_role_licence_breakdown` MCP tool — duty/privilege traversal explaining why a security role requires its licence tier (US6)
- `LicenceTier` enum with all 13 Microsoft D365 licence tiers (Operations Activity → Finance) and configurable GBP cost bands
- `ODataClient` with pagination, pre-emptive rate limiting, 401 single-retry, and 429/Retry-After handling
- `TokenManager` using MSAL client-credentials flow with in-memory token caching
- Four licence source providers: `assess-only` (default), `file` (CSV/JSON), `graph` (stub), `ppac` (stub)
- `ToolResponse` envelope with `result`, `metadata` (provider, environment, timestamp, currency), and `warnings`
- Environment-based configuration via `D365FO_BASE_URL`, `D365FO_TENANT_ID`, `D365FO_CLIENT_ID`, `D365FO_CLIENT_SECRET`
- `env.example` configuration template
- Microsoft Graph licence provider for resolving Azure AD/Entra ID licence assignments to D365 licence tiers
- `FileProvider` tier name validation with accumulated warnings for malformed entries
- Shared entity constants module eliminating duplication across tool modules
- PII redaction (`redact_pii` parameter) on all six user-facing MCP tools
- Three-tier test suite: unit (110 tests), integration (respx-mocked HTTP), and live (--live flag)
- GitHub Actions CI with Ruff linting and 80% coverage gate

### Changed

- Drilldown tool restructured from nested duties→privileges to flat parallel lists matching real D365 OData entity structure (SecurityRoleDuties + SecurityPrivileges)
- OData entity constants updated to match live D365 entity names: SecurityUserRoles, SecurityRoleDuties, SecurityPrivileges
- `ToolResponse.result` type narrowed from `Any` to `dict | list | None` (constitution §I strict typing)

### Known Limitations

- PPAC (Power Platform Admin Center) provider is a stub — not yet implemented
- Duty breakdown reflects D365 OData data model: duties and privileges are flat lists, not nested hierarchies
- Graph provider SKU-to-tier mapping covers common SKUs; custom/uncommon SKUs logged as warnings

[0.1.0]: https://github.com/yuriirask-bit/SMCP/releases/tag/v0.1.0
