# D365 F&O Telemetry Components for SMCP

This folder contains X++ source code for the SMCP Security MCP Server's D365
integration. The only component is a lightweight event handler that emits
security role change telemetry to Azure Application Insights.

> **No custom tables or OData entities required.** All data flows through
> App Insights telemetry. Login activity uses built-in `pageViews`;
> role changes use `customEvents` emitted by the event handler below.

## Components

| Class | Purpose |
|-------|---------|
| `SMCPSecurityRoleEventHandler` | Subscribes to `SecurityUserRole` insert/delete events and emits `SecurityRoleAssigned`/`SecurityRoleRevoked` custom events to App Insights |
| `SMCPTelemetryProperty` | Generic key-value property class extending `SysApplicationInsightsProperty` — allows adding arbitrary custom dimensions to telemetry events |

## Prerequisites

- D365 F&O environment with **Monitoring and Telemetry** feature enabled
  (Feature management → "Monitoring and Telemetry")
- Application Insights configured in **System administration → Monitoring
  and telemetry parameters** (Environments tab + Application Insights
  Registry tab + Configure tab with Custom metrics enabled)
- Visual Studio 2019+ with D365 F&O development tools

## Deployment

1. **Create a new D365 F&O model** in Visual Studio:
   - Model name: `SMCPSecurityModel`
   - Publisher: Your organisation
   - Layer: `USR` or `ISV`
   - Referenced models: `ApplicationPlatform`, `ApplicationFoundation`

2. **Import the X++ files** from this folder:
   - `AxClass/SMCPSecurityRoleEventHandler.xpp`
   - `AxClass/SMCPTelemetryProperty.xpp`

3. **Build the model** (Build → Build Models)

4. **Create and deploy a deployable package**
   (no database sync needed — no custom tables)

## Verification

After deployment, assign or remove a role from a user in D365. Wait 2-3
minutes for telemetry ingestion, then query App Insights:

```kusto
customEvents
| where name in ("SecurityRoleAssigned", "SecurityRoleRevoked")
| order by timestamp desc
| take 5
| project timestamp, name,
    UserId = tostring(customDimensions.UserId),
    SecurityRoleId = tostring(customDimensions.SecurityRoleId),
    SecurityRoleName = tostring(customDimensions.SecurityRoleName),
    ChangedBy = tostring(customDimensions.ChangedBy)
```

## Custom Event Properties

Each event includes these custom dimensions:

| Property | Description | Example |
|----------|-------------|---------|
| `UserId` | Affected user | `BENJAMIN` |
| `SecurityRoleId` | Role AOT name | `AUDITPOLICYMANAGER` |
| `SecurityRoleName` | Role display name | `Auditor` |
| `ChangedBy` | Who made the change | `Admin` |

D365 automatically adds: `environmentId`, `LegalEntity`, `aadTenantId`,
`ExecutionMode`, `activityId`.

## Notes

- The event handler is **fail-safe** — telemetry errors are caught and
  swallowed, never blocking the role assignment operation
- Events start capturing from the moment of deployment (no backfill)
- Works on all D365 F&O environment types (cloud-hosted, sandbox, production)
- No licence implications — uses standard X++ patterns
