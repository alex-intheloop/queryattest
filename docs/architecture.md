# Architecture

## Control plane and data plane

QueryAttest separates mutable agent input from executable database state.

### Control plane

- `SemanticCatalog` converts named metrics, dimensions and filters into parameterized SQL.
- `PolicyEngine` authorizes semantic provenance and validates the SQL AST.
- `KeyMaterial` expands one operator-managed root secret with HKDF-SHA256 into independent ticket-signing, context-HMAC and state-encryption keys.
- `TicketService` signs a versioned, canonical capability bound to one plan, principal, role set, tenant scope and policy version.
- `EncryptedStateStore` stores full plans under AES-GCM, atomically enforces the plan state machine, and records a hash-chained audit log.

### Data plane

- `PostgresGateway.preflight` uses a read-only transaction and `EXPLAIN (FORMAT JSON)`.
- Before entering the database data plane, `QueryAttestService` recompiles the stored structured intent, recomputes its statement hash and reapplies policy.
- `PostgresGateway.execute` uses a new read-only transaction, applies statement timeout and RLS context, reruns `EXPLAIN` in that transaction, rejects cost/row/relation/database-identity drift and returns at most the ticket row cap plus one sentinel row.
- `ResultVerifier` evaluates metric-owned deterministic checks.

## State machine

```text
prepared ──preflight pass──> approved ──ticket consumed──> executing
    │                            │                              │
    └─preflight reject────────> rejected                       ├─success──> executed
                                                             └─error────> failed
```

A ticket is consumed atomically before database execution. It cannot be retried or replayed, including after a database error. A caller must prepare and approve a new plan.

## Binding hierarchy

```text
natural-language question
       │ (not formally proven)
       ▼
structured QueryIntent
       │ deterministic compiler
       ▼
SQL + parameters + parameter types + SemanticBinding
       │ SHA-256 statement hash over all executable inputs
       ▼
PreparedPlan
       │ policy + EXPLAIN
       ▼
TicketClaims v2 with approved planner caps, signed with a domain-separated HMAC-SHA256 key
       │ one-time atomic consumption
       ▼
Intent recompile + hash/policy revalidation
       │ execution-time EXPLAIN
       ▼
Database execution + result digest
       │
       ▼
QueryReceipt 1.1 + redacted local-store audit hash chain
```

The natural-language-to-intent edge is intentionally marked separately. The MVP can expose evidence for review and replay, but it does not claim a theorem about language understanding.

## Error boundary

Internal exceptions are logged with stack context inside the server process. MCP clients receive a stable public error code and sanitized message. Persisted failure events record public classifications and exception types, not database messages, SQL parameters, DSNs or raw filter values.

## Remote-transport boundary

The built-in environment principal is immutable process configuration suitable for local `stdio`. It is not request authentication. Streamable HTTP therefore binds to loopback by default and refuses non-loopback hosts unless an explicit unsafe demonstration override is set. A production remote deployment must provide a request-scoped OAuth/OIDC `PrincipalProvider` before exposing the service.

## Audit boundary

The SQLite audit log is one global sequence in the local store. A response filtered to one execution cannot independently verify omitted events, so `AuditEvidence` explicitly reports `chain_scope="global_local_store"` and `independently_verifiable_from_response=false`. Production designs should export every event or chain head to externally append-only storage.

## Extension points

- Replace `PrincipalProvider` with OAuth/OIDC request claims.
- Replace `EncryptedStateStore` with PostgreSQL/Redis and KMS envelope encryption.
- Add semantic adapters for dbt Semantic Layer, Cube, MetricFlow or custom catalogs.
- Add an MCP interceptor front end to wrap existing database MCP servers.
- Add independent reconciliation executors and data-quality services.
- Emit OpenTelemetry spans and audit events to an enterprise control plane.
