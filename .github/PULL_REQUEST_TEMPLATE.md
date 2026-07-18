## Purpose

Describe the invariant, defect, or user-visible outcome addressed by this change.

## Evidence

- [ ] Success-path test added or updated
- [ ] Failure-path test added or updated
- [ ] Adversarial/regression test added for trust-boundary changes
- [ ] PostgreSQL integration test run when execution, RLS, or planner behavior changed
- [ ] Public schema, documentation, and changelog updated when applicable

## Security and compatibility impact

Explain any effect on identity, authorization, SQL compilation, tickets, encrypted state,
audit evidence, Query Receipts, or upgrade compatibility. Write `None` when not applicable.

## Verification commands

```bash
make check
# make dependency-audit
# make integration
```
