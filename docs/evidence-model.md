# Evidence model

QueryAttest does not use the word “proof” as a synonym for “the model sounded confident.” Each claim is tied to machine-checkable evidence, a trust assumption and an explicit limitation.

## Claim 1 — the agent queried the declared data

**Evidence produced**

- The agent submits a `QueryIntent` containing a named metric, dimensions, typed filters, ordering and a row limit; it does not submit SQL.
- The metric and semantic catalog carry explicit versions.
- Every field, metric expression and fixed business filter declares its physical source columns.
- At catalog load, parsed columns must exactly equal those declarations.
- The compiler emits parameterized SQL plus a `SemanticBinding` containing exact tables, columns and output fields.
- Immediately before database execution, the service recompiles the stored intent and requires the new statement hash—including parameter types—to equal the approved plan hash.

**What this proves**

The SQL that ran is the deterministic compilation of the recorded structured intent under the recorded semantic catalog.

**What this does not prove**

It does not mathematically prove that an LLM selected the correct metric for the original natural-language question. That edge requires eval/replay, user confirmation, a reviewed resolver or an independent semantic agent.

## Claim 2 — the principal was allowed to query it

**Evidence produced**

- Identity is obtained from a server-side `PrincipalProvider`, never from MCP tool arguments.
- Policy is deny-by-default across metric, table and every source column; column denials win over allows.
- Tenant scope is inserted by trusted server context and bound into the plan and ticket.
- The signed ticket binds the keyed principal fingerprint, keyed role/tenant digests and policy version. Ticket-signing, context-digest and state-encryption keys are independently derived with HKDF-SHA256.
- Policy is reapplied immediately before execution.
- PostgreSQL RLS is enabled as the final row-level boundary in the demo.

**What this proves**

Under the recorded policy version and principal context, all declared physical inputs to the query were allowed.

**Trust assumptions**

The `PrincipalProvider`, policy file and signing key must be protected. Remote deployments must replace the local environment identity provider with validated OAuth/OIDC claims.

## Claim 3 — the query was safe to execute

**Evidence produced**

- Exactly one parsed top-level `SELECT` is allowed.
- Stars, subqueries, unreviewed tables/columns, locking clauses, forbidden schemas and dangerous functions are denied.
- A literal sentinel `LIMIT` and a total bind-parameter cap are required.
- Preflight runs PostgreSQL `EXPLAIN` in a read-only transaction and checks cost, maximum plan rows and relations.
- A short-lived ticket signs the exact approved `EXPLAIN` total-cost and maximum-plan-row caps, in addition to the output-row cap. Any upward planner drift requires a new approval.
- Execution consumes that ticket atomically, starts a new read-only transaction, applies RLS context and statement timeout, then reruns `EXPLAIN` before fetching rows.
- Database user, database name, read-only status and relation set must remain consistent between preflight and execution.

**What this proves**

The executed statement satisfied the configured static and planner guards at the moment of execution, and it ran through a read-only database boundary.

**Limitations**

Planner estimates are estimates. A timeout, resource governance, least-privileged roles and read replicas remain necessary controls.

## Claim 4 — the returned answer was verified

**Evidence produced**

- The Query Receipt contains the exact semantic binding, authorization decisions, safety evidence, execution snapshot time and query hash.
- The result rows receive a deterministic digest.
- Metric-owned checks can enforce non-null, range, uniqueness and row-count conditions.
- `verified`, `partially_verified` and `failed` have explicit meanings.
- The persisted audit copy removes result rows and recursively redacts raw user, role and tenant values.
- Audit events are chained by hash and can be checked with `queryattest audit-verify`.

**What this proves**

The returned rows are traceable to one approved execution and passed the checks declared for that metric.

**What this does not prove**

A configured check is not an independent source of truth. High-risk financial or regulatory metrics should add a separately maintained reconciliation query or data-quality service. A hash chain detects edits but cannot prevent deletion or complete chain replacement; production deployments should export chain heads to append-only storage. A filtered `get_audit_evidence` response is also not independently sufficient to verify the omitted portions of the global local-store chain.

## Evidence chain

```text
Question
  │ unproven language-to-intent edge
  ▼
QueryIntent
  │ deterministic semantic compilation
  ▼
SQL + typed parameters + exact SemanticBinding
  │ statement hash
  ▼
PreparedPlan
  │ authorization + AST + preflight EXPLAIN
  ▼
Canonical signed one-time execution ticket v2
  │ recompile + hash/policy revalidation + execution EXPLAIN
  ▼
Read-only PostgreSQL result
  │ deterministic checks + result digest
  ▼
Query Receipt 1.1 + redacted hash-chained local-store evidence
```

## Recommended production acceptance rule

For low-risk analytics, accept `verified` or a reviewed `partially_verified` result. For high-risk actions, require all of the following: `verified`, no truncation, an approved metric version, an independent reconciliation check, a fresh database snapshot, and human approval before any downstream write or external action.
