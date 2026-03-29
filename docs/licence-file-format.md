# Licence File Format Reference

When `LICENCE_SOURCE=file` is set in your environment, the server reads licence assignments from a local file rather than querying Microsoft Graph or the D365 environment. This is useful for air-gapped environments, offline testing, or situations where Graph permissions are unavailable.

The file path is configured via the `LICENCE_FILE` environment variable.

---

## Supported Formats

The server detects the format automatically based on file extension (`.csv` or `.json`) and structure.

### CSV Format

The simplest format. The file must contain a header row with at minimum the two required columns.

**Required columns**:

| Column | Description |
|--------|-------------|
| `user_id` | The D365 user identifier (typically the login name or email address) |
| `licence` | The licence tier assigned to this user (see [Accepted Tier Values](#accepted-tier-values)) |

Additional columns are permitted and will be ignored.

**Example**:

```csv
user_id,licence
jsmith,Finance
aclerk,Activity
bmanager,Enterprise
sysadmin,Operations
contractor1,Task
```

Column names are case-sensitive and must appear exactly as shown.

---

### JSON Format — Dictionary

A JSON object where each key is a `user_id` and each value is the licence tier string.

```json
{
  "jsmith": "Finance",
  "aclerk": "Activity",
  "bmanager": "Enterprise",
  "sysadmin": "Operations",
  "contractor1": "Task"
}
```

This is the most compact representation and is recommended when generating licence files programmatically.

---

### JSON Format — List of Objects

A JSON array where each element is an object with `user_id` and `licence` keys. This mirrors the CSV structure and is useful when exporting from systems that produce JSON arrays.

```json
[
  {"user_id": "jsmith", "licence": "Finance"},
  {"user_id": "aclerk", "licence": "Activity"},
  {"user_id": "bmanager", "licence": "Enterprise"},
  {"user_id": "sysadmin", "licence": "Operations"},
  {"user_id": "contractor1", "licence": "Task"}
]
```

---

## Accepted Tier Values

The `licence` field must be one of the following values (case-sensitive):

| Value | Description |
|-------|-------------|
| `None` | No licence assigned |
| `SelfServe` | Self-service licence |
| `Task` | Task (formerly "Device") licence |
| `Functional` | Functional user licence |
| `Enterprise` | Enterprise full-user licence |
| `Server` | Server licence (non-interactive) |
| `Universal` | Universal licence |
| `Activity` | Activity licence (light-use) |
| `Finance` | Finance app-specific licence |
| `SCM` | Supply Chain Management app-specific licence |
| `Commerce` | Commerce app-specific licence |
| `Project` | Project Operations app-specific licence |
| `HR` | Human Resources app-specific licence |
| `Operations` | Operations activity licence |

Values outside this list will cause a validation warning at startup and the affected users will be treated as having an unknown licence.

---

## Behaviour for Missing Users

If a user exists in the D365 environment but has no entry in the licence file, the server cannot determine their licence status. These users will:

- Appear in tool responses with licence set to `"unknown"`
- Be flagged in the `detect_under_licensed_users` and `assess_user_licence_requirements` tools with a warning indicating their licence status is unknown
- **Not** be included in over-licence detection results (unknown licence cannot be compared against role requirements)

To suppress these warnings, either add the missing users to the licence file or switch to a live licence source (`LICENCE_SOURCE=graph` or `LICENCE_SOURCE=d365`) that can resolve all users automatically.

---

## Example `.env` Configuration

```dotenv
LICENCE_SOURCE=file
LICENCE_FILE=/path/to/licences.csv
```

On Windows, use forward slashes or escape backslashes:

```dotenv
LICENCE_FILE=C:/data/licences.json
```
