# SoD Conflict Ruleset File Format

The D365 F&O Security MCP Server loads Segregation of Duties (SoD) conflict rules from an external JSON file. This document describes the file format so you can author your own ruleset.

## Configuration

Set the `SOD_RULES_FILE` environment variable to the path of your ruleset file:

```dotenv
SOD_RULES_FILE=/path/to/your-sod-rules.json
```

Or in your MCP client config (Claude Desktop, Claude Code):

```json
{
  "env": {
    "SOD_RULES_FILE": "/path/to/your-sod-rules.json"
  }
}
```

## File Structure

```json
{
  "version": "1.0",
  "metadata": {
    "name": "My Organisation SoD Ruleset",
    "description": "Custom SoD rules for our D365 F&O environment",
    "author": "Security Team",
    "created": "2026-01-15"
  },
  "privileged_roles": [
    "-SYSADMIN-",
    "SYSTEMADMINISTRATOR",
    "SECURITYADMINISTRATOR"
  ],
  "rules": [
    {
      "id": "SOD-AP-001",
      "name": "Vendor Maintenance vs Payment Approval",
      "category": "accounts_payable",
      "risk_level": "Critical",
      "description": "A user who can create or modify vendor records should not also be able to approve payments to those vendors.",
      "duty_group_a": {
        "name": "Maintain vendor master",
        "duties": ["VendTableMaintain"]
      },
      "duty_group_b": {
        "name": "Approve vendor payments",
        "duties": ["VendPaymProposalApprove", "LedgerJournalizeTransactionPost"]
      }
    }
  ]
}
```

## Field Reference

### Top Level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Schema version. Currently `"1.0"`. |
| `metadata` | object | Yes | Descriptive information about the ruleset. |
| `privileged_roles` | array of strings | No | Role identifiers considered high-privilege for dormant account detection. If empty, the system falls back to roles participating in SoD rules plus known admin roles. |
| `rules` | array of objects | Yes | The conflict rules. |

### metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name for the ruleset. |
| `description` | string | No | What this ruleset covers. |
| `author` | string | No | Who created or maintains the ruleset. |
| `created` | string | No | Creation or last-modified date. |

### rules[] (each rule)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (e.g., `"SOD-AP-001"`). Must be unique across all rules. |
| `name` | string | Yes | Human-readable rule name. |
| `category` | string | Yes | Category slug (e.g., `"accounts_payable"`, `"general_ledger"`). Used for filtering. |
| `risk_level` | string | Yes | One of: `"Critical"`, `"High"`, `"Medium"`. |
| `description` | string | Yes | Plain-English explanation of why this combination is risky. Should be understandable by a non-technical compliance officer. |
| `duty_group_a` | object | Yes | First conflicting duty group. |
| `duty_group_b` | object | Yes | Second conflicting duty group. |

### duty_group_a / duty_group_b

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name (e.g., `"Maintain vendor master"`). |
| `duties` | array of strings | Yes | One or more D365 duty identifiers. At least one required. |

## How Matching Works

The system uses **ANY-to-ANY** matching:

- A violation triggers when a user holds **at least one duty** from group A **and** at least one duty from group B.
- Duties are collected across all the user's assigned roles, including sub-roles.
- Duplicate duties (same duty from multiple roles) are counted once.

## Risk Levels

| Level | Weight | Guidance |
|-------|--------|----------|
| `Critical` | 3 | Immediate remediation required. Direct financial fraud risk. |
| `High` | 2 | Should be remediated within the current review cycle. |
| `Medium` | 1 | Monitor and remediate when feasible. |

Risk weights are used to compute per-user risk scores and the security health score.

## Finding D365 Duty Identifiers

To find the correct duty identifiers for your rules:

1. Use the `get_role_duty_tree` tool to inspect a role's duties:
   > "What duties does the Accounts Payable Clerk role contain?"

2. Use the `get_user_security_profile` tool to see a specific user's duty assignments.

3. In D365 F&O, navigate to **System administration → Security → Security configuration** to browse the role/duty/privilege hierarchy.

## Validation

The server validates the ruleset on startup:

- **Missing or invalid fields**: The rule is skipped with a warning. Other valid rules still load.
- **Duplicate rule IDs**: The duplicate is skipped with a warning.
- **Empty rules array**: A warning is emitted but the server starts (SoD tools return "no ruleset configured").
- **Missing file**: The server starts but SoD tools return an error with setup guidance.

Use `get_sod_conflict_matrix` to verify your loaded ruleset after startup.

## Example

See `examples/sod-rules-sample.json` in the repository for a working example with 5 rules across 4 categories.
