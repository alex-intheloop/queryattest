# Threat model

## Protected assets

- tenant-scoped database rows
- sensitive columns such as customer identifiers
- database availability
- semantic metric integrity
- execution authorization and audit evidence

## Attacker capabilities considered

- a model invents metric names, fields, filters, SQL fragments or ticket strings
- a model attempts prompt injection through database content
- a client modifies an approved query before execution
- a client replays an old ticket
- a principal tries to use another tenant, role, plan or execution ID
- a query attempts multi-statement, DDL/DML, dangerous functions, unbounded result sets or excessive planner cost
- local state files are copied and inspected
- audit rows are edited after the fact
- malformed, non-canonical or duplicate-key ticket documents are supplied
- a client triggers an internal database/parser exception and attempts to recover secrets from the error
- a remote deployment accidentally exposes one process-wide environment identity to multiple users

## Defenses

| Threat | Defense |
|---|---|
| Arbitrary SQL | No raw SQL tool; deterministic semantic compiler. |
| SQL injection in filters | PostgreSQL bind parameters. |
| Query changed after approval | Parameter-type-aware statement hash in the signed ticket, encrypted immutable plan lookup, execution-time intent recompilation and hash recomputation. |
| Ticket forgery or parser ambiguity | HKDF-separated HMAC key, canonical base64url/JSON, duplicate-key rejection, version/key ID checks, bounded lifetime and token size. |
| Ticket replay | Short TTL and atomic one-time consumption, including concurrent attempts. |
| Identity/tenant swapping | Identity never comes from tool arguments; keyed ticket bindings cover principal/roles/tenant. |
| Unauthorized or omitted columns | Deny-wins policy plus exact parsed-vs-declared physical-column provenance at catalog load and query validation. |
| Cross-tenant reads | Server-injected tenant predicate and forced PostgreSQL RLS. |
| DDL/DML/locking | SELECT-only AST policy and read-only database transaction/login. |
| Plan drift or expensive queries | Preflight `EXPLAIN`, execution-transaction `EXPLAIN` recheck, database user/name comparison, total-cost/row guards and statement timeout. |
| Excessive result output | Literal sentinel LIMIT, exact sentinel-row invariant and ticket row cap. |
| Local plan disclosure or substitution | HKDF-separated AES-GCM key, authenticated plan ID and POSIX owner-only state-file mode. |
| Silent audit modification | SHA-256 event hash chain and verification command. |
| Result/identity retention | Rows are returned to the caller but not persisted; nested user/role/tenant values are redacted and only a digest plus evidence remains. |
| Exception-data leakage | Stable public error codes/messages; internal exceptions are logged server-side and audit failures retain only safe classification. |
| Accidental remote identity sharing | Non-loopback Streamable HTTP is refused by default; environment identity is documented as local-only. |

## Residual risks and non-goals

1. **Natural-language interpretation is not proven.** An agent can still choose the wrong allowed metric. Eval/replay, user-visible semantic binding, metric-owner review and independent resolvers reduce this risk.
2. **SQLGlot is not the final security boundary.** Parser gaps or dialect changes are possible. Least privilege, read-only transactions and PostgreSQL RLS must remain enforced.
3. **HMAC is symmetric.** Anyone with the root secret can derive the signing key and mint tickets. Ticket payload context identifiers are keyed digests, but the token is signed rather than encrypted. Production deployments should use managed key custody, rotation and optionally asymmetric signing.
4. **A local attacker with process memory access can obtain secrets and query results.** Host/process isolation is outside the package boundary.
5. **A hash chain detects mutation but does not prevent deletion or full-chain replacement.** Export chain heads to an external append-only/WORM system.
6. **EXPLAIN estimates are not execution guarantees.** Statement timeout, workload controls and replicas remain necessary.
7. **Configured checks are only as good as their definitions.** Financial/high-risk answers should use independently maintained reconciliation paths.
8. **Remote authentication is not implemented in the MVP.** Environment identity is suitable for local stdio only. The unsafe non-loopback override prevents accidental configuration, not malicious use after it is enabled.
9. **Result data still enters the MCP client/model context.** Configure allowed metrics and columns conservatively, and add output masking for sensitive use cases.
10. **Local SQLite is not a durable distributed trust store.** Host compromise, rollback, deletion, backup substitution and multi-node races require a transactional remote store plus external anchoring.
11. **No independent audit has been completed.** Static analysis, tests and coverage reduce known defect risk but are not a security certification.
