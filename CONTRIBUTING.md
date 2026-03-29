# Contributing

Thank you for contributing to the D365 F&O Security MCP project. This document describes the development workflow, test strategy, and code standards required for all contributions.

---

## Development Setup

### Prerequisites

- Python 3.11+
- A D365 F&O sandbox environment (for integration and live tests)
- Azure AD app registration with Dynamics ERP permissions (see `docs/azure-ad-setup.md`)

### Install in Editable Mode

```bash
pip install -e ".[dev]"
```

This installs the package plus all development dependencies (pytest, ruff, coverage, etc.) defined in the `[project.optional-dependencies]` section of `pyproject.toml`.

### Environment Variables

Copy `.env.example` to `.env` and fill in your credentials before running any tests that contact a live environment:

```bash
cp .env.example .env
```

---

## Running Tests

The project uses a three-tier test pyramid. Each tier has a distinct purpose and runtime cost; all three must pass before a pull request is merged.

### Tier 1 — Unit Tests

Fast, isolated tests with no external dependencies. All external I/O is mocked.

```bash
pytest tests/unit/
```

Unit tests must pass with no network access and no `.env` file present. They form the bulk of the test suite.

### Tier 2 — Integration Tests

Tests that exercise the interaction between internal components (e.g., provider + tool layer) using recorded or stubbed HTTP responses. No live D365 connection required.

```bash
pytest tests/integration/
```

Integration tests are skipped automatically in CI unless explicitly opted in (they require the `--integration` marker flag):

```bash
pytest --integration tests/integration/
```

### Tier 3 — Live Tests

End-to-end tests that call a real D365 F&O environment. These require all environment variables to be set and a reachable D365 sandbox.

```bash
pytest --live tests/live/
```

Live tests are never run in CI. They are intended for local validation against a real environment before raising a pull request for changes that touch provider or OData logic.

### Three-Tier Test Pyramid Rule

- **Unit tests** must cover all business logic, edge cases, and error paths.
- **Integration tests** must cover component boundaries and contract compliance.
- **Live tests** must cover end-to-end happy paths for each tool.

Do not write logic in live tests that belongs in unit tests. Keep each tier focused on its layer.

---

## Coverage

The minimum coverage threshold for the `tools/` package is **80%**. Check coverage with:

```bash
pytest --cov=src/d365fo_security_mcp/tools tests/unit/
```

To view a line-by-line report:

```bash
pytest --cov=src/d365fo_security_mcp/tools --cov-report=term-missing tests/unit/
```

Pull requests that reduce `tools/` coverage below 80% will not be accepted.

---

## Linting

All code must pass `ruff` with zero warnings:

```bash
ruff check src/ tests/
```

Auto-fix safe issues before committing:

```bash
ruff check --fix src/ tests/
```

Formatting is also enforced via `ruff format`:

```bash
ruff format src/ tests/
```

---

## Branch Naming

Branches must follow the `###-feature-name` convention, where `###` is a zero-padded incremental number matching the associated issue or spec:

```
001-d365fo-security-mcp
002-graph-licence-provider
015-sod-detection
```

Use hyphens, not underscores. The branch number should correspond to the spec directory under `specs/`.

---

## Pull Request Checklist

Before opening a pull request, verify:

- [ ] `pytest tests/unit/` passes with zero failures
- [ ] `ruff check src/ tests/` passes with zero warnings
- [ ] `ruff format src/ tests/` has been run and changes are committed
- [ ] `pytest --cov=src/d365fo_security_mcp/tools tests/unit/` shows 80%+ coverage
- [ ] New tools or providers have corresponding unit and integration tests
- [ ] No credentials, `.env` files, or secrets are included in the diff
- [ ] Branch name follows `###-feature-name` convention

---

## Commit Style

Write commit messages in the imperative mood with a concise subject line (72 characters or fewer). Reference the task ID where applicable:

```
feat: add Graph licence provider (T045)
fix: handle empty role list in SoD detection (T052)
test: add unit tests for licence file parser (T061)
```
