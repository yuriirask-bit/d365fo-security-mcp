# D365 F&O Custom Telemetry for SMCP

SMCP uses Azure Application Insights as the data backbone for both login
activity tracking and security role change auditing. No custom OData entities
or custom tables are required — only a lightweight X++ event handler that emits
telemetry to App Insights.

## Prerequisites

- D365 F&O environment with "Enable Custom Telemetry + Application Insights"
  enabled (**System administration** → **Setup** → **Monitoring and telemetry parameters**)
- App Insights connection string configured in the MCP server
  (`APP_INSIGHTS_CONNECTION_STRING`)
- Monitoring Reader RBAC role granted to the service principal
  (see [azure-ad-setup.md Step 5c](azure-ad-setup.md))

## Login Activity Tracking (No X++ Required)

D365 F&O automatically emits `pageView` events to App Insights for every
interactive session. The MCP server queries these to derive login sessions.
No custom X++ code is needed.

See [App Insights setup](../README.md#app-insights-setup-optional--login-activity).

## Security Role Change Tracking (X++ Event Handler Required)

The `get_security_change_log` MCP tool queries `customEvents` from App Insights
to show role assignment changes. This requires deploying a single X++ class that
emits telemetry when roles are assigned or revoked.

> **Why not Database Logging?** Database Logging for the `SecurityUserRole` table
> was tested and does NOT work reliably for capturing role assignment changes.
> The event handler approach is real-time and reliable.

### How It Works

1. The `SMCPSecurityRoleEventHandler` class subscribes to `insert` and `delete`
   events on the `SecurityUserRole` table
2. On each event, it emits a custom telemetry event to App Insights:
   - **`SecurityRoleAssigned`** — when a role is added to a user
   - **`SecurityRoleRevoked`** — when a role is removed from a user
3. Each event includes: `UserId`, `SecurityRoleId`, `SecurityRoleName`,
   `ChangedBy` (who made the change)
4. The MCP server queries these events via the App Insights API using KQL

### Custom Event Properties

| Property | Description | Example |
|----------|-------------|---------|
| `name` | Event type | `SecurityRoleAssigned` or `SecurityRoleRevoked` |
| `customDimensions.UserId` | Affected user | `jsmith` |
| `customDimensions.SecurityRoleId` | Role AOT name | `AccountsPayableClerk` |
| `customDimensions.SecurityRoleName` | Role display name | `Accounts Payable Clerk` |
| `customDimensions.ChangedBy` | Who made the change | `admin` |
| `timestamp` | When (auto-set by App Insights) | `2026-03-27T14:00:00Z` |

### KQL Query (used by the MCP server)

```kusto
customEvents
| where name in ("SecurityRoleAssigned", "SecurityRoleRevoked")
| where timestamp >= ago(30d)
| project
    timestamp,
    ChangeType = iff(name == "SecurityRoleAssigned", "Added", "Removed"),
    UserId = tostring(customDimensions.UserId),
    SecurityRoleId = tostring(customDimensions.SecurityRoleId),
    SecurityRoleName = tostring(customDimensions.SecurityRoleName),
    ChangedBy = tostring(customDimensions.ChangedBy)
| order by timestamp desc
```

## Source Code

The X++ source code is in the [`d365-xpp/`](../d365-xpp/) folder:

```
d365-xpp/
├── README.md                               # Deployment instructions
└── SMCPSecurityModel/
    └── AxClass/
        └── SMCPSecurityRoleEventHandler.xpp # Telemetry event handler
```

> **Removed files**: `SMCPSecurityRoleAuditTable.xpp`,
> `SMCPSecurityRoleChangeEntity.xml`, and `SMCPUserSessionLogEntity.xml` are
> no longer needed. The custom table and OData entity have been replaced by
> App Insights telemetry.

## Deployment

1. Create a new D365 F&O model (`SMCPSecurityModel`) in Visual Studio
2. Import `SMCPSecurityRoleEventHandler.xpp` into the project
3. Build the model and synchronize (no database changes needed — no custom tables)
4. Create and deploy a deployable package

### Verify

After deployment, assign or remove a role from a user in D365. Then query
App Insights (wait 2-3 minutes for telemetry to arrive):

```kusto
customEvents
| where name in ("SecurityRoleAssigned", "SecurityRoleRevoked")
| order by timestamp desc
| take 5
```

You should see the role change event with all custom properties.

## Integration with SMCP

Once the event handler is deployed and App Insights is configured:

```bash
# Via MCP tool
get_security_change_log(days=30)
```

If the event handler is not deployed or no role changes have occurred, the tool
returns an empty result with guidance on deploying the event handler.
