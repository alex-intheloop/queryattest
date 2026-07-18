# Contributing

Contributions should preserve the project's evidence claims rather than only make tests pass. A change to tickets, identity, policy, semantic compilation, database execution, persisted state, or audit evidence is security-sensitive.

## Development setup

Requirements: Python 3.11 or newer, `uv`, and PostgreSQL only for integration tests.

```bash
uv sync --frozen --extra dev
make check
```

`make check` is deterministic and offline except for dependency installation. Dependency vulnerability lookup is separate because it requires network access:

```bash
make dependency-audit
```

Run live PostgreSQL tests with a database initialized from `demo/init.sql`:

```bash
export TEST_DATABASE_URL='postgresql://queryattest_reader:queryattest_reader@127.0.0.1:5432/queryattest'
make integration
```

## Pull-request quality requirements

A pull request should include:

- a focused explanation of the invariant being added or preserved;
- tests for success and failure paths;
- an adversarial or regression test for a fixed trust-boundary defect;
- documentation updates when a public schema, claim, limitation, or operator action changes;
- a compatibility note for ticket, encrypted state, policy, semantic catalog, or Query Receipt changes.

Before submitting:

```bash
make check
make dependency-audit   # when network access is available
make integration        # for database/execution/RLS changes
```

Do not weaken an assertion solely to increase coverage. Do not return raw database errors, SQL parameters, identity attributes, secrets, or query rows in persisted audit evidence.

## Design rules

- The MCP interface must not accept arbitrary SQL.
- Identity and tenant scope must not come from tool arguments.
- Authorization is deny by default; explicit denies win.
- A ticket must remain bound to one principal, plan, statement hash, policy version, expiry, row cap, and cost cap.
- Execution must recompile intent, recompute the statement hash, reapply policy, and recheck the database plan.
- PostgreSQL least privilege and RLS remain final boundaries; parser checks are defense in depth.
- Evidence wording must distinguish attested execution from unproven natural-language interpretation.

Report suspected exploitable weaknesses through the private process in [SECURITY.md](SECURITY.md).
