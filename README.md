# QueryAttest

**Evidence-backed database execution for AI agents.**

QueryAttest is a policy and evidence layer for AI agents that query PostgreSQL through MCP. It deliberately does not expose `execute_sql(sql: string)`. An agent submits a structured intent against reviewed, versioned business metrics; QueryAttest compiles parameterized SQL, validates exact provenance and authorization, checks the SQL AST and PostgreSQL execution plan, and issues a short-lived one-time execution ticket. At execution time it recompiles the intent, reapplies policy, reruns `EXPLAIN` inside a read-only transaction, and executes only the immutable approved plan.

Every approved execution returns a structured **Query Receipt** recording what ran, why it was allowed, which data it accessed, which safety controls were enforced, and which deterministic verification checks passed.

> Status: `v0.1.1` (alpha), not independently audited. The repository attests that database execution matches the recorded **structured intent**, policy, and configured evidence checks; it does not prove that an LLM always selects the correct business metric from natural language.

Quality gates and known limits:

- [Repository quality gates](docs/quality-gates.md)
- [Implementation status](docs/implementation-status.md)
- [Threat model](docs/threat-model.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Publishing checklist](docs/publishing.md)
- [Changelog](CHANGELOG.md)

## Why this exists

A database connector can prove that a SQL statement ran. It normally cannot prove all four of these claims:

1. **Right data:** the statement implements a declared, versioned business metric.
2. **Allowed data:** the authenticated principal may access every metric, table, and column involved.
3. **Safe query:** the statement is a single bounded `SELECT`, inexpensive enough, tenant-scoped, and executed read-only.
4. **Verified answer:** configured checks passed and the returned evidence is traceable to one immutable query and result digest.

QueryAttest makes those claims explicit and machine-readable rather than hiding them inside prompts.

## Trust flow

```text
MCP client / agent
      │ structured intent
      ▼
prepare_query
      ├─ semantic metric compiler
      ├─ parameterized SQL
      ├─ table/column provenance
      └─ policy authorization
      │ immutable plan_id
      ▼
preflight_query
      ├─ SQLGlot AST validation
      ├─ SELECT-only / one statement / no SELECT *
      ├─ PostgreSQL EXPLAIN
      ├─ cost and estimated-row guards
      ├─ relation reconciliation
      └─ signed, short-lived, principal-bound ticket
      │ one-time ticket
      ▼
execute_approved_query
      ├─ signature + plan hash + policy version verification
      ├─ atomic one-time ticket consumption
      ├─ intent recompilation + statement-hash recomputation
      ├─ policy revalidation
      ├─ read-only transaction + RLS tenant context
      ├─ execution-time EXPLAIN cost/row/relation recheck
      ├─ statement timeout + returned-row cap
      ├─ deterministic metric checks
      └─ hash-chained audit event
      │
      ▼
Query Receipt
```

## Implemented MCP tools

| Tool | Purpose |
|---|---|
| `list_metrics` | Lists only metrics visible to the immutable principal. |
| `describe_metric` | Returns metric version, dimensions, filter fields, source and checks. |
| `prepare_query` | Compiles structured intent into an immutable parameterized plan. |
| `preflight_query` | Runs policy + `EXPLAIN`, then issues a signed execution ticket. |
| `execute_approved_query` | Executes exactly that plan once and returns a Query Receipt. |
| `get_audit_evidence` | Returns redacted evidence and hash-chained audit events. |

FastMCP derives MCP input and output schemas from the Pydantic types. Query Receipts therefore use MCP structured output rather than an untyped text blob.

## Security properties in this MVP

- The model never supplies a database identity. For local `stdio`, identity comes from immutable environment configuration.
- SQL is compiled from a reviewed semantic catalog; there is no arbitrary SQL MCP tool. Parsed field, metric and base-filter columns must exactly match their declared provenance.
- Filter values are PostgreSQL bind parameters, not string interpolation. Input lists, strings and total bind-parameter count are bounded.
- A 32-byte-or-longer root secret is expanded with HKDF-SHA256 into separate ticket-signing, identity-context-HMAC and state-encryption keys. Ticket v2 includes a key identifier and rejects non-canonical or duplicate-key JSON.
- HMAC execution tickets bind plan ID, statement hash, principal fingerprint, keyed role/tenant digests, policy version, output-row cap, the approved `EXPLAIN` cost/row caps and expiry. Upward planner drift therefore requires a new prepare/preflight cycle. Raw user, role and tenant values are not embedded in the readable ticket payload.
- Tickets are one-time-use and plans are encrypted at rest with AES-GCM. On POSIX systems the local SQLite state file is restricted to owner read/write permissions.
- Audit events form a SHA-256 hash chain. Query results and raw identity values are not persisted; only redacted receipt evidence and a result digest are stored. A filtered audit response is not independently sufficient to verify the global local-store chain.
- Before execution, the stored plan is recompiled from its structured intent, its statement hash is recomputed and policy is reapplied.
- PostgreSQL queries run inside `READ ONLY` transactions with `statement_timeout` and `row_security = on`; `EXPLAIN` is rerun in that same transaction to catch cost, row, relation, database-user or database-name drift after approval.
- The demo login has `default_transaction_read_only = on`, no privileged role flags, and the table has forced PostgreSQL RLS.
- AST policy is defense in depth. The database role and RLS remain the final authorization boundary.
- Public MCP errors use stable error codes and sanitized messages; raw internal/database exceptions are logged server-side rather than returned to the agent.

See [docs/evidence-model.md](docs/evidence-model.md) for the exact proof claims and [docs/threat-model.md](docs/threat-model.md) for non-goals and residual risks.

## Quick start

### 1. Install

```bash
uv sync --frozen --extra dev
cp .env.example .env
```

Generate and place a new secret in `.env`:

```bash
uv run queryattest generate-secret
```

Do not use the placeholder or the Docker demo secret outside a disposable local environment.

### 2. Start the demo PostgreSQL database

```bash
docker compose up -d postgres
```

The demo creates:

- `analytics.orders`
- tenant rows for `tenant-a` and `tenant-b`
- the least-privileged `queryattest_reader` login
- forced RLS using `current_setting('app.tenant_id', true)`

### 3. Validate the trust boundary

```bash
uv run queryattest validate-config
uv run queryattest doctor
make check
```

`make check` verifies formatting, Ruff, strict mypy, Bandit, branch coverage (minimum 80%), tests, and package builds. Dependency auditing is separate because it needs current online vulnerability data:

```bash
make dependency-audit
```

### 4. Inspect the MCP server

```bash
uv run mcp dev src/queryattest/server.py --with-editable .
```

Or run directly over stdio:

```bash
uv run queryattest-server
```

For a local-loopback Streamable HTTP demo:

```bash
QUERYATTEST_TRANSPORT=streamable-http uv run queryattest-server
```

The default MCP endpoint is `http://127.0.0.1:8000/mcp`.

The bundled environment principal is not remote authentication. The server refuses a non-loopback Streamable HTTP bind unless `QUERYATTEST_ALLOW_INSECURE_REMOTE_HTTP=true` is set explicitly; that override is only for isolated disposable demonstrations.

## Example agent flow

The agent first discovers the available metric contract:

```json
{
  "tool": "describe_metric",
  "arguments": {"metric_name": "net_revenue"}
}
```

It then submits structured intent, not SQL:

```json
{
  "tool": "prepare_query",
  "arguments": {
    "question": "What was net revenue by channel in June 2026?",
    "metric": "net_revenue",
    "dimensions": ["channel"],
    "filters": [
      {"field": "completed_at", "op": "gte", "value": "2026-06-01T00:00:00Z"},
      {"field": "completed_at", "op": "lt", "value": "2026-07-01T00:00:00Z"}
    ],
    "order_by": [{"field": "net_revenue", "direction": "desc"}],
    "limit": 100
  }
}
```

The server compiles a query similar to this, with the tenant parameter inserted by trusted server context:

```sql
SELECT
  o.channel AS "channel",
  COALESCE(SUM(o.net_amount), 0) AS "net_revenue"
FROM analytics.orders AS o
WHERE (o.status = 'completed')
  AND o.tenant_id = $1
  AND o.completed_at >= $2
  AND o.completed_at < $3
GROUP BY o.channel
ORDER BY "net_revenue" DESC
LIMIT 101
```

`LIMIT 101` is intentional: one sentinel row lets the server report whether a 100-row answer was truncated.

After `preflight_query(plan_id)`, the exact ticket must be passed to `execute_approved_query(ticket)`. The model cannot modify the SQL between approval and execution.

## Query Receipt

A successful response contains the data plus evidence resembling:

```json
{
  "receipt_version": "1.1",
  "status": "verified",
  "answer": [{"channel": "organic", "net_revenue": "1250000.00"}],
  "semantic": {
    "binding": {
      "metric": "net_revenue",
      "metric_version": "3",
      "source_tables": ["analytics.orders"],
      "source_columns": [
        "analytics.orders.channel",
        "analytics.orders.completed_at",
        "analytics.orders.net_amount",
        "analytics.orders.status",
        "analytics.orders.tenant_id"
      ]
    },
    "compiled_from_structured_intent": true,
    "natural_language_mapping_proven": false
  },
  "authorization": {
    "user_id": "alex",
    "roles": ["finance_analyst"],
    "tenant_scope": "tenant-a",
    "policy_version": "2026-07-16.1"
  },
  "safety": {
    "ast_validated": true,
    "structured_intent_recompiled": true,
    "statement_hash_recomputed": true,
    "policy_revalidated_at_execution": true,
    "read_only_transaction": true,
    "database_user": "queryattest_reader",
    "database_name": "queryattest",
    "database_identity_basis": ["database_user", "database_name"],
    "database_identity_matches_preflight": true,
    "relations_rechecked_in_execution_transaction": true,
    "statement_timeout_ms": 5000,
    "max_rows": 100,
    "truncated": false
  },
  "verification": [
    {"name": "ticket_signature_and_binding", "passed": true},
    {"name": "structured_intent_recompiled", "passed": true},
    {"name": "policy_revalidated_at_execution", "passed": true},
    {"name": "execution_time_explain_within_policy", "passed": true},
    {"name": "non_null:net_revenue", "passed": true},
    {"name": "min:net_revenue", "passed": true}
  ],
  "provenance": {
    "query_hash": "...",
    "result_digest": "...",
    "snapshot_time": "..."
  }
}
```

`verified` means all configured deterministic checks passed. `partially_verified` means execution and provenance are verified but a page was truncated or the metric has no domain checks. `failed` means a configured check failed.

This status attests the recorded execution and configured checks. It is not a claim that natural-language metric selection or the business value is independently proven.

## Policy as code

`config/policy.yaml` controls:

- role-to-metric grants
- table and column allowlists
- deny-wins column patterns
- maximum returned rows
- maximum planner rows and total cost
- maximum bind-parameter count
- statement timeout
- ticket and plan TTLs
- forbidden schemas and PostgreSQL functions

`config/semantics.yaml` controls:

- data products and tenant columns
- named dimensions/filter fields
- versioned metric expressions
- fixed business filters
- exact source-column provenance
- deterministic result checks

Both files use strict Pydantic validation and reject unknown keys. Semantic expressions are parsed at startup; comments, bind placeholders, stars, undeclared tables, unqualified columns and provenance mismatches are rejected.

## Eval and replay

A scenario records intent and expected security/semantic properties:

```bash
uv run queryattest replay tests/scenarios/net_revenue.yaml
uv run queryattest replay tests/scenarios/net_revenue.yaml --online
uv run queryattest replay tests/scenarios/net_revenue.yaml --execute
```

- Offline mode tests semantic compilation and policy without a database.
- `--online` adds PostgreSQL `EXPLAIN` assertions.
- `--execute` adds Query Receipt and optional numeric-tolerance assertions.

This is intended for CI regression testing across catalog, policy, database and agent changes.

## dbt manifest bootstrap

```bash
uv run queryattest import-dbt target/manifest.json \
  --output config/semantics.imported.yaml \
  --tenant-column tenant_id
```

The importer creates conservative data-product and field stubs. It deliberately does **not** guess business metric expressions; those require human review and explicit source-column/check declarations.

## MCP client installation

The official Python SDK supports direct installation into compatible local clients:

```bash
uv run mcp install src/queryattest/server.py \
  --name "QueryAttest" \
  --with-editable . \
  -f .env
```

A generic stdio configuration is available in [examples/mcp-client-config.json](examples/mcp-client-config.json).

## Production hardening before remote deployment

The included identity provider is intentionally for local `stdio`. A remote deployment should replace it with validated OAuth/OIDC claims and add:

- OAuth 2.1 protected-resource metadata and audience validation
- per-user and per-tenant rate limits
- centralized KMS/HSM ticket keys with rotation and key IDs
- durable transactional state storage instead of local SQLite
- append-only/WORM audit export and SIEM integration
- PostgreSQL read replicas where appropriate
- RLS tests for every tenant-bearing table
- private-network database access and TLS verification
- metric-owner approval and catalog version promotion
- independent reconciliation checks for high-risk financial metrics
- data masking/tokenization for allowed sensitive outputs
- OpenTelemetry SDK/exporter configuration (`queryattest[otel]`)

The MCP specification requires servers to validate inputs, enforce access controls, rate-limit invocations and sanitize outputs. See the official tool and authorization specifications:

- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/docs/tutorials/security/authorization

## Development

```bash
uv sync --frozen --extra dev
make check
```

Integration tests run when `TEST_DATABASE_URL` points at a PostgreSQL database initialized from `demo/init.sql`:

```bash
make integration
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for repository invariants and pull-request requirements.

## License

Apache-2.0.
