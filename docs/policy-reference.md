# Policy and semantic catalog reference

## Policy precedence

- Unknown roles deny the request.
- At least one effective role must allow the metric.
- Every source table and source column must match an allow pattern.
- Any matching `deny_columns` pattern wins over allows.
- SQL, planner and database guards can only add denials; they cannot override authorization.

Patterns use Python `fnmatch` syntax. Prefer narrow, schema-qualified patterns in production.

## SQL safety

`deny_select_star` rejects AST `Star` nodes. Metric definitions should use `COUNT(primary_key)`, not `COUNT(*)`, when this guard is enabled.

`require_schema_qualified_tables` prevents `search_path` ambiguity.

`forbidden_functions` is a defense-in-depth list and includes file access, advisory locks, backend control and other side-effect functions in the sample policy. Keep database privileges restrictive even when a function is not listed. `max_bind_parameters` bounds generated placeholder count in addition to per-filter input limits.

## Semantic provenance

Every field and metric declares its physical source columns. Fixed business predicates declare `base_filter_columns` separately. At catalog load, SQLGlot parses each expression and the parsed column set must exactly equal the declaration. During compilation these declarations become `SemanticBinding.source_columns`; authorization and a second exact AST reconciliation use that binding. A missing tenant predicate or fixed business predicate therefore appears as missing physical provenance and is denied.

The semantic file is trusted operator configuration and should be code-reviewed. It is strict-schema validated, parsed through the PostgreSQL SQLGlot dialect, and prohibited from referencing undeclared tables.

## Result checks

Supported MVP checks:

- `non_null`
- `min`
- `max`
- `unique`
- `row_count_min`
- `row_count_max`

Checks run only on returned rows. A truncated result is therefore marked `partially_verified`.
