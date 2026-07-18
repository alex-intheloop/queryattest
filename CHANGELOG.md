# Changelog

All notable changes to this alpha project are documented here. The project does not promise state, ticket, or evidence-schema compatibility before `1.0`.

## 0.1.1 — QueryAttest public alpha

### Project identity

- Establish the public project name **QueryAttest** and the evidence artifact name **Query Receipt**.
- Publish the `queryattest` Python package, `queryattest` CLI, `queryattest-server` entry point, and `QUERYATTEST_` configuration prefix.
- Rename the public execution evidence model to `QueryReceipt` and replay expectation field to `receipt_status`.
- Use QueryAttest-specific ticket, cryptographic-domain, telemetry, Docker, database-fixture, and local-state identifiers.

### Security and correctness

- Derive separate ticket-signing, context-HMAC, and state-encryption keys with HKDF-SHA256 from one operator-managed root secret.
- Introduce execution ticket format v2 with a key identifier, canonical JSON validation, duplicate-key rejection, strict lifetime checks, bounded token size, and caps derived from the approved `EXPLAIN` cost/row evidence.
- Replace unkeyed identity hashes with keyed context digests.
- Construct semantic query statements as SQLGlot ASTs instead of interpolating a generated `SELECT ... FROM ...` string.
- Include parameter types in the immutable statement hash.
- Revalidate database name as well as database user between preflight and execution.
- Reject malformed `EXPLAIN` documents, unexpected sentinel-row counts, non-read-only transactions, relation drift, and execution-time cost/row-estimate drift.
- Redact persisted answer rows and nested identity values, including role evidence.
- Stop exposing raw internal exception details through MCP responses and audit events.
- Prevent non-loopback Streamable HTTP unless an explicit unsafe override is set.
- Restrict the SQLite state file to owner read/write permissions on POSIX systems.
- Revoke the demo role's ability to create temporary database objects.

### Reliability and maintainability

- Close every SQLite connection deterministically; `ResourceWarning` is now a test failure.
- Add strict input bounds and catalog identifier validation.
- Reject non-finite JSON/database numbers, ambiguous local timestamps, blank identity claims, and malformed ticket configuration before they can enter approval evidence.
- Expand typed state restoration and state-machine tests across rejected, expired, executing, succeeded, failed, tampered, and unknown-record paths.
- Expand tests to cover ticket tampering, encrypted-state tampering, concurrent one-time consumption, audit-chain tampering, MCP error boundaries, replay failures, verifier redaction, and PostgreSQL gateway guards.
- Enforce branch coverage of at least 80%.
- Add Python 3.11–3.13 CI, PostgreSQL 17 integration CI, formatting, lint, strict typing, Bandit, dependency audit, package build, and wheel smoke tests.
- Pin every third-party GitHub Action to a reviewed full commit SHA and enforce per-job timeouts.
- Add deterministic Makefile quality targets and repository quality documentation.
- Replace build-environment package-mirror references with public PyPI lockfile URLs.
- Add public-repository governance, conduct, issue, pull-request, Dependabot, publishing, and Docker ignore policies.
- Run the demo MCP container as a non-root user with a read-only root filesystem, dropped capabilities, and `no-new-privileges`; verify the image build and runtime user in CI.

### Evidence schema

- Bump `QueryReceipt.receipt_version` to `1.1`.
- Add database name and the database-identity comparison basis to safety evidence.
- Clarify that returned audit evidence represents a global chain in the local store and is not independently verifiable from a filtered response alone.

### Alpha compatibility note

Version `0.1.1` uses QueryAttest-specific cryptographic domains, ticket identity, and state encryption. Existing plans or tickets from earlier alpha and pre-public builds are not compatible. Because this state is short-lived, stop the old process and remove or archive its state database before upgrading. Do not copy active tickets across project identifiers or releases.

## 0.1.0 — initial alpha

- Structured metric intent, semantic compilation, policy authorization, PostgreSQL preflight, one-time execution tickets, read-only execution, result checks, Query Receipts, audit chain, replay framework, and dbt manifest bootstrap.
