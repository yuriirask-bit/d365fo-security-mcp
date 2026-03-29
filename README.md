# D365 F&O Security & Licence Intelligence MCP Server

Exposes security analysis, licence intelligence, and SoD detection as MCP
tools consumable by AI agents and copilots.

## Quick Start

### Prerequisites

- Python 3.10+
- A D365 F&O environment with OData access
- An Azure AD / Entra ID app registration with `Dynamics ERP` →
  `CustomService.FullAccess` permission

### 1. Install

```bash
git clone https://github.com/yuriirask-bit/SMCP.git
cd SMCP
pip install -e ".[dev]"
```

### 2. Configure

```bash
cp env.example .env
# Edit .env with your D365 environment URL and Azure AD credentials
```

### 3. Run

```bash
d365fo-security-mcp
```

The server starts on stdio transport (standard MCP protocol).

### 4. Connect

MCP clients (Claude Desktop, Claude Code, etc.) launch the server as a
subprocess. Environment variables **must** be passed in the client's MCP
configuration — the server does not inherit your shell environment or read
`.env` when launched this way.

**Claude Desktop** — edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "d365fo-security": {
      "command": "d365fo-security-mcp",
      "env": {
        "D365FO_BASE_URL": "https://your-env.operations.dynamics.com",
        "D365FO_TENANT_ID": "your-tenant-id",
        "D365FO_CLIENT_ID": "your-client-id",
        "D365FO_CLIENT_SECRET": "your-client-secret",
        "LICENCE_SOURCE": "graph"
      }
    }
  }
}
```

**Claude Code** — edit `.claude/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "d365fo-security": {
      "command": "d365fo-security-mcp",
      "env": {
        "D365FO_BASE_URL": "https://your-env.operations.dynamics.com",
        "D365FO_TENANT_ID": "your-tenant-id",
        "D365FO_CLIENT_ID": "your-client-id",
        "D365FO_CLIENT_SECRET": "your-client-secret",
        "LICENCE_SOURCE": "graph"
      }
    }
  }
}
```

> **Important:** After changing env values in MCP config, you must fully
> restart the client (not just reconnect the server) for the new values to
> take effect.

**MCP Inspector** (for local testing — reads `.env` automatically):

```bash
npx @modelcontextprotocol/inspector d365fo-security-mcp
```

### 5. First Tool Call

Ask your AI agent:

> "What licence does each user in our D365 environment need?"

## Available Tools

| Tool | Description |
|------|-------------|
| `assess_user_licence_requirements` | Calculate minimum licence tier per user. Supports `tier_filter`, `min_role_count`, and `include_roles` for filtered/compact queries |
| `detect_over_licensed_users` | Find users on too-expensive licence tiers |
| `detect_under_licensed_users` | Find users at compliance risk (under-licensed) |
| `what_if_role_change` | Simulate role changes and see licence/cost impact. Now includes SoD conflict projection alongside licence impact |
| `get_licence_summary_report` | Aggregate licence consumption overview with compact per-user list |
| `get_role_licence_breakdown` | Explain why a role requires its licence tier. Use `summary_only=true` for large roles to omit the privileges array |
| `get_security_server_config` | Inspect server configuration, D365 connectivity, licence source setup, tool capabilities, and limitations |
| `validate_licence_source` | Test licence source connectivity with structured validation breakdown and remediation guidance |

### SoD Conflict Detection & Security Analysis

| Tool | Description |
|------|-------------|
| `detect_sod_violations` | Run SoD conflict rules against all users or a specific user |
| `get_sod_conflict_matrix` | Inspect the configured SoD conflict ruleset with category filter |
| `get_user_security_profile` | Full role → duty → privilege hierarchy for a user with SoD violations. Supports `summary_only` parameter for agent-friendly compact output |
| `get_high_risk_users` | Rank users by SoD violation count and severity |
| `get_role_duty_tree` | Role hierarchy with sub-roles and optional SoD conflict annotations |
| `get_all_user_role_assignments` | Complete user-role assignment matrix. Supports `exclude_service_accounts` to filter out service accounts |
| `get_org_security_map` | Legal entity scoped access map |
| `get_security_change_log` | Role assignment changes over time (via App Insights custom events — requires X++ event handler) |
| `find_dormant_privileged_accounts` | Privileged users with no recent login (three-source: App Insights + Database Logging + Graph) |
| `run_user_access_review` | Quarterly compliance access review list |
| `get_security_health_score` | Aggregate security posture score (0–100) with dimensional breakdown |

> **Tip:** Most user-scanning tools accept an `exclude_service_accounts` parameter that uses Provider-based native detection to filter out service and system accounts from results.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `D365FO_BASE_URL` | Yes | — | D365 F&O environment URL |
| `D365FO_TENANT_ID` | Yes | — | Azure AD tenant ID |
| `D365FO_CLIENT_ID` | Yes | — | App registration client ID |
| `D365FO_CLIENT_SECRET` | Yes | — | App registration client secret |
| `LICENCE_SOURCE` | No | `assess-only` | Licence data provider: `assess-only`, `file`, `graph`, `ppac` |
| `LICENCE_FILE_PATH` | No | — | Path to licence CSV/JSON (when `LICENCE_SOURCE=file`) |
| `CURRENCY` | No | `GBP` | ISO 4217 currency code for cost calculations |
| `D365FO_GRAPH_SCOPE` | No | `https://graph.microsoft.com/.default` | OAuth scope for Microsoft Graph API calls |
| `STALE_THRESHOLD_DAYS` | No | `7` | Days after which licence source data is considered stale |
| `D365FO_VERSION` | No | — | D365 application version override (e.g., `10.0.46`). Auto-detected from environment if not set |
| `SOD_RULES_FILE` | No | — | Path to SoD conflict ruleset JSON file. See [docs/sod-ruleset-format.md](docs/sod-ruleset-format.md) |
| `APP_INSIGHTS_CONNECTION_STRING` | No | — | Azure Application Insights connection string for login activity tracking. Requires Monitoring Reader RBAC role. See [App Insights setup](#app-insights-setup-optional--login-activity) |

## App Insights Setup (Optional — Login Activity)

Tools like `find_dormant_privileged_accounts`, `run_user_access_review`, and
`get_security_health_score` use login activity data to detect dormant accounts.
The primary source for D365 login sessions is Azure Application Insights.

### 1. Enable Application Insights in D365 F&O

1. In the D365 F&O environment, go to **System administration** →
   **Setup** → **Monitoring and telemetry parameters**
2. Enable **Custom Telemetry + Application Insights**
3. Paste your App Insights **Instrumentation Key** into the configuration field
4. Save and allow a few minutes for telemetry to start flowing

### 2. Get the Connection String

1. In the [Azure Portal](https://portal.azure.com), navigate to your
   Application Insights resource
2. On the **Overview** page, copy the **Connection String** (not just the
   instrumentation key — the full string starting with
   `InstrumentationKey=...;IngestionEndpoint=...;ApplicationId=...`)

### 3. Grant the Service Principal Read Access

The MCP server's service principal (the same app registration used for D365
OData access) needs the **Monitoring Reader** role on the App Insights resource.

> **Why not API keys?** App Insights API keys were deprecated by Microsoft and
> retired in March 2026. Azure AD authentication with RBAC is the only
> supported method going forward.

**Option A — Azure Portal (UI):**

1. Navigate to your Application Insights resource
2. Go to **Access control (IAM)** → **Add** → **Add role assignment**
3. Role: search for and select **Monitoring Reader**
4. Members: select **User, group, or service principal**, click
   **+ Select members**
5. Search for your app registration name (e.g., `ICU-DEV1`) and select it
6. Click **Review + assign**

**Option B — Azure CLI:**

```bash
# Get the service principal object ID
SP_ID=$(az ad sp show --id <your-D365FO_CLIENT_ID> --query id -o tsv)

# Get the App Insights resource ID
AI_SCOPE=$(az monitor app-insights component show \
  -g <resource-group> --app <app-insights-name> --query id -o tsv)

# Assign Monitoring Reader role
az rest --method put \
  --url "${AI_SCOPE}/providers/Microsoft.Authorization/roleAssignments/$(uuidgen)?api-version=2022-04-01" \
  --body "{
    \"properties\": {
      \"roleDefinitionId\": \"/subscriptions/<subscription-id>/providers/Microsoft.Authorization/roleDefinitions/43d0d8ad-25c7-4714-9337-8ba259a9fe05\",
      \"principalId\": \"${SP_ID}\",
      \"principalType\": \"ServicePrincipal\"
    }
  }"
```

> **Note:** `43d0d8ad-25c7-4714-9337-8ba259a9fe05` is the built-in role
> definition ID for **Monitoring Reader** — it is the same across all Azure
> subscriptions.

### 4. Configure the MCP Server

Add the connection string to your environment configuration:

```dotenv
APP_INSIGHTS_CONNECTION_STRING=InstrumentationKey=xxxxx;IngestionEndpoint=https://...;ApplicationId=xxxxx
```

Or in your MCP client config (`claude_desktop_config.json` / `.claude/mcp.json`):

```json
{
  "env": {
    "APP_INSIGHTS_CONNECTION_STRING": "InstrumentationKey=xxxxx;IngestionEndpoint=https://...;ApplicationId=xxxxx"
  }
}
```

### 4. Verify

After a user logs into D365 and navigates a few pages, run:

```kusto
pageViews
| summarize LoginTime=min(timestamp) by user_Id, session_Id
| order by LoginTime desc
```

in the App Insights **Logs** blade to confirm telemetry is arriving.

### How It Works

D365 F&O emits `pageView` events to Application Insights for every interactive
session. The MCP server queries these via the App Insights API to derive login
sessions — summarising the first page view per user/session as the login
timestamp. No custom X++ entities are required.

> **Note:** App Insights is one of three login data sources. The server also
> queries D365 Database Logging (`SysUserLog` via `DatabaseLogs` entity) and
> Microsoft Graph `signInActivity` in parallel. The most recent timestamp from
> any source wins. All sources are optional — the tools degrade gracefully with
> warnings when sources are unavailable. Graph `signInActivity` requires an
> Entra ID P1/P2 (Premium) licence on the tenant — see
> [Step 5b](docs/azure-ad-setup.md#5b-add-auditlog-permission-optional--graph-sign-in-activity).

## How It Works

```
MCP Client (Claude, Copilot) → MCP Server → OData API → D365 F&O
                                    ↓
                             Licence Source
                        (assess-only | file | graph)
```

The server queries D365 F&O security metadata via OData, calculates licence
requirements per user, and exposes the results as MCP tools.

## Licence Source Options

| Source | Description | Setup Required |
|--------|-------------|---------------|
| `assess-only` | Calculate requirements only — no assigned licence comparison | None (default) |
| `file` | Compare against a CSV/JSON file of assigned licences | Set `LICENCE_SOURCE=file` and `LICENCE_FILE_PATH` |
| `graph` | Query Azure AD / Entra ID for assigned licences | Set `LICENCE_SOURCE=graph` + Graph API permissions |
| `ppac` | Power Platform Admin Center (not yet implemented) | — |

## Common Agent Prompts

### Licence Intelligence
- "What licence does each user in our D365 environment need?"
- "Which users are over-licensed and how much could we save?"
- "Are any users under-licensed and at risk of enforcement?"
- "What happens to licence costs if I remove the Finance Controller role from user jsmith?"
- "Give me an executive summary of our D365 licence spend"
- "Why does the Accountant role require a Finance licence?"

### SoD & Security Analysis
- "Are there any segregation of duties violations in our environment?"
- "What SoD rules are you checking against?"
- "Show me everything about user jsmith's security access"
- "Who are our highest-risk users?"
- "Are there any dormant privileged accounts?"
- "Give me a full access review list for our quarterly audit"
- "How healthy is our D365 security overall?"

## Limitations

- The PPAC licence provider is not yet implemented (stub only)
- The Graph provider covers common Microsoft 365 SKU GUIDs; uncommon SKUs are logged as warnings
- Duty/privilege breakdown uses flat lists matching the D365 OData data model structure
- Single-environment operation — multi-environment comparison is a future capability

## Development

```bash
pip install -e ".[dev]"
ruff check src/ tests/
pytest --cov=src/d365fo_security_mcp/tools
```

## Licence

MIT
