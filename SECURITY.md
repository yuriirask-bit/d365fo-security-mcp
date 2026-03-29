# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues via [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) using the **Report a vulnerability** button on the Security tab of this repository. This ensures the report is handled privately until a fix is available.

When submitting a report, include:
- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if safe to share)
- Any suggested mitigations you are aware of

We aim to acknowledge reports within 5 business days and to publish a fix or advisory within 90 days of confirmation.

---

## Access Model

The D365 F&O Security MCP server operates in **read-only mode**. It queries D365 F&O via OData and the Microsoft Graph API but never writes data back to either system. No write permissions are requested, granted, or used.

---

## Required Permissions

The Azure AD app registration should be scoped to the minimum set of permissions necessary for the features you enable:

| Permission | API | Type | Required for |
|------------|-----|------|-------------|
| `CustomService.FullAccess` | Dynamics ERP | Application | All D365 OData queries (core functionality) |
| `User.Read.All` | Microsoft Graph | Application | `LICENCE_SOURCE=graph` only |

Do not grant additional permissions beyond those listed above. In particular:
- Do not grant `Directory.ReadWrite.All` or any write-scoped Graph permission
- Do not grant `Files.ReadWrite`, `Mail.Send`, or other unrelated Microsoft 365 permissions
- Do not use Delegated permissions — the server uses the client credentials flow (app-only)

If you are not using the Graph licence provider, omit the `User.Read.All` permission entirely.

---

## Protecting Credentials

- **Never commit `.env` or any file containing credentials to source control.** The `.gitignore` file excludes `.env` by default; do not override this.
- Store `AZURE_CLIENT_SECRET` in a secrets manager (e.g., Azure Key Vault, HashiCorp Vault) in production environments.
- Rotate client secrets regularly and immediately if a potential exposure is suspected.
- Use short-lived secrets where possible (the Azure Portal allows expiry periods of up to 24 months; prefer shorter durations).

---

## PII Redaction

Tool responses may include user identifiers (login names, display names). The `redact_pii` parameter, available on all tools that return user data, replaces identifiable fields with a deterministic hash. Enable this when:

- Storing or logging tool responses
- Passing responses to external systems or third-party AI models
- Operating under data minimisation requirements (e.g., GDPR)

Example (MCP tool call):

```json
{
  "tool": "detect_over_licensed_users",
  "arguments": {
    "redact_pii": true
  }
}
```

The hash is stable within a single server session, allowing correlation within a session without exposing raw identifiers.

---

## Network Security

- The server communicates outbound only — it does not listen on any port or accept inbound connections.
- All HTTP requests to D365 and Microsoft Graph are made over TLS (HTTPS). Plain-text HTTP is rejected.
- If deploying behind a proxy, ensure the proxy does not strip or downgrade TLS.

---

## Dependency Security

Dependencies are pinned in `uv.lock`. Run the following to check for known vulnerabilities in the dependency tree:

```bash
pip-audit
```

Dependency updates that introduce high or critical CVEs will block pull request merges.
