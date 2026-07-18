# Repository quality gates

Version `0.1.1` treats quality as a set of executable gates and explicit evidence limits, not as a claim of production readiness.

## Required offline gates

The canonical local command is:

```bash
make check
```

It runs:

| Gate | Command | Enforced property |
|---|---|---|
| Formatting | `ruff format --check .` | Stable source formatting |
| Lint | `ruff check .` | Python correctness, maintainability, and Bandit-compatible security rules |
| Static typing | `mypy src` | Strict typing for package code |
| Source security scan | `bandit -q -r src/queryattest` | No unreviewed Bandit findings in shipped source |
| Unit and boundary coverage | `pytest ... --cov-branch` | At least 80% branch coverage |
| Packaging | `uv build` | Wheel and source distribution can be built from the repository |

Pytest converts leaked file/socket/database handles surfaced as `ResourceWarning` into failures.

## Network and live-system gates

These are separate because they require external infrastructure:

```bash
make dependency-audit
make integration
```

- `pip-audit` checks the resolved Python environment against current vulnerability databases and therefore requires network access.
- PostgreSQL integration tests require `TEST_DATABASE_URL` and an initialized fixture. CI runs them against PostgreSQL 17 using `demo/init.sql`.

## CI matrix

GitHub Actions runs:

- unit tests on Python 3.11, 3.12, and 3.13;
- formatting, Ruff, strict mypy, Bandit, branch coverage, and dependency audit;
- PostgreSQL 17 integration and RLS tests;
- wheel/source build and installation smoke tests;
- container build, non-root-user assertion, and CLI smoke test.
- full-commit-SHA-pinned third-party Actions and explicit job timeouts.

## Trust-boundary regression coverage

The suite includes negative tests for:

- weak or non-domain-separated key material;
- non-finite canonical values, ambiguous local timestamps, blank identity claims, and malformed ticket-service configuration;
- ticket modification, non-canonical encoding, duplicate JSON keys, expiry, wrong principal/role/tenant, and key mismatch;
- encrypted plan tampering and plan-ID substitution;
- concurrent attempts to consume one one-time ticket;
- invalid plan/execution state transitions, expired-plan persistence, typed parameter restoration, and encrypted-state authentication failures;
- audit-event mutation and persisted identity/result redaction;
- semantic provenance mismatch, catalog subqueries, output collisions, and placeholder/type mismatch;
- arbitrary/multi-statement SQL, forbidden AST nodes, relations, schemas, and functions;
- malformed `EXPLAIN`, non-read-only transactions, relation drift, cost/row drift, and sentinel-row invariant failure;
- raw exception leakage through MCP tools and audit failure records;
- unsafe non-loopback Streamable HTTP configuration;
- verifier failures containing sensitive raw values.

## Coverage interpretation

The 80% threshold is a floor, not proof that all behaviors are correct. Priority is given to branches on authorization, state transitions, cryptographic binding, database execution, redaction, and failure handling. Coverage-only tests that do not assert an invariant are not considered sufficient.

## Evidence limitations

Passing these gates demonstrates repository consistency under the tested models and fixtures. It does not replace:

- an independent security audit;
- PostgreSQL privilege/RLS review for a real schema;
- load, fault-injection, and long-running concurrency tests;
- managed key rotation and disaster recovery exercises;
- verification that an LLM selected the correct business metric;
- independent reconciliation for regulated or financial answers.

## Public-release hygiene

The repository test suite also enforces that the committed lockfile contains no internal package-mirror URLs and that public community, security, contribution, issue, pull-request, dependency-update, Docker-ignore, and publishing files are present and parseable. Generated build artifacts, local state, secrets, caches, and coverage output are excluded from the source archive.
