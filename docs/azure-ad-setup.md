# Azure AD / Entra ID App Registration Setup

This guide walks through registering the D365 F&O Security MCP application in Azure Active Directory (Microsoft Entra ID) and configuring the necessary permissions for OData access to Dynamics 365 Finance & Operations.

## Prerequisites

- An Azure subscription with access to the Azure Portal
- Global Administrator or Application Administrator role in Entra ID (required to grant admin consent)
- A D365 F&O environment URL

---

## Step-by-Step Registration

### 1. Create the App Registration

1. Navigate to the [Azure Portal](https://portal.azure.com)
2. Go to **Microsoft Entra ID** → **App registrations** → **New registration**
3. Fill in the registration form:
   - **Name**: `D365 F&O Security MCP` (or a name appropriate for your organisation)
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**: Leave blank (not required for service-to-service authentication)
4. Click **Register**

### 2. Note the Application Identifiers

After registration, copy the following values from the **Overview** page — you will need them for your environment configuration:

- **Application (client) ID** → `D365FO_CLIENT_ID`
- **Directory (tenant) ID** → `D365FO_TENANT_ID`

### 3. Add Dynamics ERP API Permission

1. In your app registration, go to **API permissions** → **Add a permission**
2. Select **APIs my organization uses** and search for `Dynamics ERP`
3. Select **Dynamics ERP** from the results
4. Choose **Application permissions**
5. Tick **CustomService.FullAccess**
6. Click **Add permissions**

### 4. Grant Admin Consent

Admin consent must be granted by a Global Administrator or Application Administrator before the application can authenticate.

1. Still on the **API permissions** page, click **Grant admin consent for [your tenant]**
2. Confirm the prompt — the status column should update to a green checkmark showing **Granted for [your tenant]**

> **Note**: Without admin consent, all API calls will return `401 Unauthorized` or `403 Forbidden` regardless of whether the permission is listed.

### 5. Add Microsoft Graph Permissions (Required for `LICENCE_SOURCE=graph`)

If you plan to use the Graph licence provider (`LICENCE_SOURCE=graph`) to retrieve actual licence assignments from Entra ID, add the following permissions:

1. **API permissions** → **Add a permission** → **Microsoft Graph**
2. Choose **Application permissions**
3. Search for and tick **User.Read.All** and **Directory.Read.All**
4. Click **Add permissions**
5. Click **Grant admin consent for [your tenant]** again to cover the new permissions

> **Note:** Without Graph permissions, the server runs in `assess-only` mode — it calculates what each user *needs* but cannot compare against actual licence assignments. Set `LICENCE_SOURCE=graph` to enable full over/under-licensed detection.

### 5b. Add AuditLog Permission (Optional — Graph Sign-In Activity)

This step adds Microsoft Graph `signInActivity` as a login data source. It
provides Entra ID sign-in timestamps including non-interactive sign-ins that
App Insights does not capture.

> **Prerequisite: Entra ID P1 or P2 (Premium) licence.** The `signInActivity`
> endpoint requires a Premium licence on the tenant. Without it, Graph returns
> 403 regardless of API permissions. If your tenant does not have Entra ID
> Premium, skip this step — App Insights and Database Logging are sufficient
> for most use cases.

**Via Azure Portal:**

1. In your app registration, go to **API permissions** → **Add a permission**
2. Select **Microsoft Graph** → **Application permissions**
3. Search for and tick **AuditLog.Read.All**
4. Click **Add permissions**
5. Click **Grant admin consent for [your tenant]**

**Via Azure CLI:**

```bash
# Add AuditLog.Read.All permission
az ad app permission add \
  --id <D365FO_CLIENT_ID> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role

# Grant admin consent for all permissions
az ad app permission admin-consent --id <D365FO_CLIENT_ID>
```

> **Note:** `b0afded3-3588-46d8-8b3d-9842eff778da` is the built-in permission
> ID for `AuditLog.Read.All` — it is the same across all tenants.

**Verify it works:**

```bash
# Get a Graph token
TOKEN=$(python -c "
import msal
app = msal.ConfidentialClientApplication(
    '<D365FO_CLIENT_ID>',
    authority='https://login.microsoftonline.com/<D365FO_TENANT_ID>',
    client_credential='<D365FO_CLIENT_SECRET>')
r = app.acquire_token_for_client(
    scopes=['https://graph.microsoft.com/.default'])
print(r['access_token'])")

# Test signInActivity
curl -s "https://graph.microsoft.com/v1.0/users?\$top=1&\$select=userPrincipalName,signInActivity" \
  -H "Authorization: Bearer $TOKEN"
```

If you see user data with `signInActivity` timestamps, it's working. If you
get a 403 with `Authentication_RequestFromNonPremiumTenantOrB2CTenant`, your
tenant needs an Entra ID P1/P2 licence.

> **Without this permission or without Premium**, dormant account detection and
> access reviews still work using App Insights and/or Database Logging data.
> Graph sign-in activity is an optional enhancement, not a requirement.

### 5c. Set Up Application Insights (Optional — Login Activity from D365)

Application Insights is the primary source for D365 F&O login session data. It requires zero custom X++ entity deployment — only enabling a built-in D365 feature.

**In the D365 F&O environment:**

1. Go to **System administration** → **Setup** → **Monitoring and telemetry parameters**
2. Enable **Custom Telemetry + Application Insights**
3. Paste the **Instrumentation Key** from your Application Insights resource
4. Save and wait a few minutes for telemetry to start flowing

**In the Azure Portal (get the connection string):**

1. Navigate to your Application Insights resource
2. On the **Overview** page, copy the full **Connection String** (starts with `InstrumentationKey=...;IngestionEndpoint=...;ApplicationId=...`)

**Verify telemetry is flowing:**

Log into D365 F&O, navigate a few pages, then run this query in the App Insights **Logs** blade:

```kusto
pageViews
| summarize LoginTime=min(timestamp) by user_Id, session_Id
| order by LoginTime desc
```

You should see at least one row per login session.

**Grant the service principal read access to App Insights:**

The MCP server authenticates to the App Insights API using the same service principal (app registration) it uses for D365 OData. This requires the **Monitoring Reader** RBAC role on the App Insights resource.

> **Why not API keys?** App Insights API keys were deprecated by Microsoft and
> retired in March 2026. Azure AD authentication with RBAC is the only
> supported method going forward.

**Via Azure Portal:**

1. Navigate to your Application Insights resource
2. Go to **Access control (IAM)** → **Add** → **Add role assignment**
3. Role: search for and select **Monitoring Reader**
4. Members: select **User, group, or service principal**, click **+ Select members**
5. Search for your app registration name (the same one from Step 1, e.g., `D365 F&O Security MCP`) and select it
6. Click **Review + assign**

**Via Azure CLI:**

```bash
# Get the service principal object ID (use your D365FO_CLIENT_ID)
SP_ID=$(az ad sp show --id <D365FO_CLIENT_ID> --query id -o tsv)

# Get the App Insights resource ID
AI_SCOPE=$(az monitor app-insights component show \
  -g <resource-group> --app <app-insights-name> --query id -o tsv)

# Assign Monitoring Reader role (43d0d8ad... is the built-in role ID)
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

> **How it works:** D365 emits `pageView` events to App Insights for every interactive page navigation. The MCP server derives login sessions by summarising the first page view per `user_Id`/`session_Id`. This replaces the need for any custom X++ data entity for login tracking.

> **Note:** App Insights captures interactive sessions only (not batch jobs). For batch session tracking, Database Logging on `SysUserLog` or Graph `signInActivity` complement this source.

### 6. Create a Client Secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Enter a **Description** (e.g., `smcp-prod`) and choose an **Expiry** period
3. Click **Add**
4. **Immediately copy the secret Value** — it will not be shown again after you navigate away

> Store the secret securely (e.g., Azure Key Vault or a secrets manager). Never commit it to source control.

### 7. Configure Environment Variables

The server reads configuration from environment variables. How you provide
them depends on how you run the server:

- **Local development / MCP Inspector**: add to `.env` in the project root
- **Claude Desktop**: add to `env` block in `%APPDATA%\Claude\claude_desktop_config.json`
- **Claude Code**: add to `env` block in `.claude/mcp.json`
- **GitHub Copilot (VS Code)**: add to `github.copilot.chat.mcp.servers` in VS Code `settings.json`, or create a `.vscode/mcp.json` file in the project root

> **Important:** MCP clients (Claude Desktop, Claude Code, Copilot) launch the
> server as a subprocess and do **not** read your `.env` file. You must pass
> all required variables in the client's MCP configuration.

**Required variables:**

```dotenv
D365FO_BASE_URL=https://<your-environment>.operations.dynamics.com
D365FO_TENANT_ID=<Directory (tenant) ID>
D365FO_CLIENT_ID=<Application (client) ID>
D365FO_CLIENT_SECRET=<Client secret value>
```

**Optional — licence source:**

```dotenv
# Enable live licence detection via Microsoft Graph (requires Step 5 permissions)
LICENCE_SOURCE=graph
```

**Optional — login activity (App Insights):**

```dotenv
# Enable D365 login session tracking via Application Insights (requires Step 5c)
APP_INSIGHTS_CONNECTION_STRING=InstrumentationKey=xxxxx;IngestionEndpoint=https://...;LiveEndpoint=https://...;ApplicationId=xxxxx
```

Without `LICENCE_SOURCE`, the server defaults to `assess-only` mode which
calculates licence requirements but cannot detect over/under-licensed users.
See the main [README](../README.md#licence-source-options) for all available
licence source options.

---

## Troubleshooting

### `AADSTS7000215` — Invalid client secret

The client secret value is incorrect or has expired.

- Regenerate the secret under **Certificates & secrets** → **New client secret**
- Update `D365FO_CLIENT_SECRET` in your configuration with the new value
- Secrets cannot be recovered after leaving the creation page; always copy them immediately

### `AADSTS700016` — Application not found in the directory

The `D365FO_CLIENT_ID` or `D365FO_TENANT_ID` does not match an existing app registration in the target tenant.

- Verify both values from the **Overview** page of your app registration
- Confirm you are authenticating against the correct tenant (single-tenant apps will not work cross-tenant)

### `403 Forbidden` on OData requests

The app registration is missing the Dynamics ERP permission or admin consent has not been granted.

- Confirm **Dynamics ERP → CustomService.FullAccess** appears under **API permissions**
- Confirm the permission status shows **Granted** (green checkmark) — a listed permission without consent has no effect
- If consent was recently granted, allow a few minutes for propagation

### `401 Unauthorized`

The bearer token is invalid, expired, or was issued for the wrong audience/scope.

- Verify `D365FO_BASE_URL` matches the actual environment hostname — the audience in the token must match
- Check that the token has not expired; the MCP server handles token refresh automatically, but misconfigured clock skew on the host can cause issues
- Confirm `D365FO_TENANT_ID` is the tenant that owns the D365 environment

### `LICENCE_SOURCE` not taking effect

The server reports `assess-only` mode despite `LICENCE_SOURCE=graph` being configured.

- MCP clients cache environment variables at session start — a full client restart (not just server reconnect) is required after changing env values
- Verify the variable is in the correct config file for your client (see Step 7 above)
- Run the `get_security_server_config` tool to check `licence_source.configured_source` and `limitations` for diagnostic hints
