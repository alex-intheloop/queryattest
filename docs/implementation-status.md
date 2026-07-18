# Implementation status — v0.1.1 alpha

## Release posture

This release is a quality-hardened reference implementation. It is suitable for architecture review, local demonstrations, replay/evaluation work, and controlled PostgreSQL proofs of concept. It is **not independently audited** and should not be represented as a production security gateway without additional controls and review.

## Implemented

- Six MCP tools with generated structured input/output schemas.
- Reviewed semantic catalog with strict schema and SQL-identifier validation.
- Exact parsed-vs-declared provenance validation for fields, metrics and fixed business filters.
- SQLGlot AST construction for the final `SELECT`, typed PostgreSQL bind parameters, tenant injection, sentinel row limit and parameter-count bounds.
- Deny-by-default role policy for metrics, tables and columns; explicit column denies win.
- SQLGlot AST guard for one bounded `SELECT`, explicit outputs, exact placeholders/types/tables/columns, forbidden operations, functions and schemas.
- PostgreSQL preflight using read-only `EXPLAIN (FORMAT JSON)` with cost, plan-row, relation, database-user and database-name evidence.
- HKDF-SHA256 domain separation for ticket signing, context digests and state encryption.
- Ticket v2 with canonical encoding, duplicate-key rejection, validated issuer/audience/key ID, principal/role/tenant/policy binding, TTL bounds, cost/row caps and one-time use.
- AES-GCM encrypted plan state with typed parameter restoration, finite-number enforcement, UTC-aware timestamps and authenticated plan-ID binding.
- Atomic plan state machine preventing concurrent ticket replay.
- Execution-time intent recompilation, parameter-type-aware statement-hash recomputation and policy revalidation.
- Execution-transaction `EXPLAIN` recheck to catch cost, row-estimate, relation or database-identity drift.
- Read-only PostgreSQL transaction, RLS context, statement timeout and exact sentinel-row invariant.
- Query Receipt `1.1` with semantic, authorization, safety, verification and provenance evidence.
- Redacted persisted evidence and SHA-256 hash-chained audit events with explicit local/global-chain limitations.
- Stable public MCP error codes and sanitized messages; raw internal failures remain in server logs.
- Offline/online/execute replay framework and conservative dbt manifest importer.
- Optional OpenTelemetry spans around MCP tool operations.
- Docker demo with a non-privileged read-only PostgreSQL role, no temporary-object privilege and forced tenant RLS.
- Demo MCP container runs as a non-root user with a read-only root filesystem, dropped Linux capabilities and `no-new-privileges`.
- Public source lockfile references PyPI/Files.pythonhosted rather than the private build mirror.
- Non-loopback Streamable HTTP refusal unless an explicit unsafe demo override is configured.

## Quality validation performed in this build environment

- `ruff format --check .`: passed.
- `ruff check .`: passed.
- `mypy src` in strict mode: passed.
- `bandit -q -r src/queryattest`: passed with no reported findings.
- Unit/boundary suite: 158 passed; four live PostgreSQL integration cases were deselected.
- Branch coverage: 85.32%, above the enforced 80% threshold.
- `ResourceWarning` is configured as an error; the suite passed without leaked SQLite connections.
- GitHub Actions workflow parsed successfully and defines Python 3.11–3.13, static-analysis, PostgreSQL 17, package, and non-root container jobs.
- Source distribution and wheel build: passed.
- Built-wheel import, version, CLI and MCP schema smoke tests: passed.

## External validation

- A live PostgreSQL test was not run in this build environment because Docker, Podman, `postgres`, and `psql` were unavailable. GitHub Actions now provisions PostgreSQL 17, initializes `demo/init.sql`, and runs the integration/RLS suite.
- `pip-audit` completed against the locked environment on 2026-07-18 and reported no known dependency vulnerabilities. The unpublished local `queryattest` package itself was skipped because it is not yet available from PyPI; CI repeats the audit for every change.

## Deliberate limitations

- Natural-language-to-metric selection is exposed as an unproven edge, not claimed as formally verified.
- Remote OAuth/OIDC identity is not implemented; environment identity is local-stdio/demo only.
- SQLite state is single-node and not a production control-plane datastore.
- Local root-secret handling has domain-separated keys and a key ID but no managed rotation, KMS/HSM custody, or multi-key verification window.
- Result checks are metric-owned checks, not an independent reconciliation source.
- No write tools are exposed.
- No output masking/tokenization layer is included.
- Audit hash chains detect mutation but require external append-only anchoring to resist deletion or complete replacement.
- Planner estimates and branch coverage are evidence, not execution or security proofs.
- Load, fault-injection, long-running concurrency, backup/restore and disaster-recovery testing remain out of scope for this alpha.

## Compatibility note

`0.1.1` uses QueryAttest-specific cryptographic domains and ticket identity; encrypted plans and tickets from earlier alpha or pre-public builds are not compatible. Stop the old process and remove or archive its short-lived state database before upgrading. Tickets must not be carried across project identifiers or releases.

## Recommended next milestone

Before a remote production pilot: validated OAuth/OIDC claims, PostgreSQL-backed transactional state, KMS-managed rotating keys, external append-only audit anchoring, rate limits, output policy/masking, schema-specific RLS adversarial tests, load/fault tests, and an independent security assessment.
