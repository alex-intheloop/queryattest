from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, ClassVar

import sqlglot
from sqlglot import exp

from queryattest.config import PolicyConfig, RoleGrant
from queryattest.models import (
    CompiledQuery,
    PolicyDecision,
    PolicyOutcome,
    Principal,
)


class PolicyViolation(PermissionError):
    def __init__(self, message: str, decisions: list[PolicyDecision]) -> None:
        super().__init__(message)
        self.decisions = decisions


@dataclass(frozen=True)
class PolicyReport:
    allowed: bool
    decisions: list[PolicyDecision]


class PolicyEngine:
    """Authorization and SQL-shape enforcement for compiled semantic queries."""

    FORBIDDEN_NODE_NAMES: ClassVar[set[str]] = {
        "Alter",
        "Analyze",
        "Attach",
        "Cache",
        "Call",
        "Command",
        "CTE",
        "Do",
        "Commit",
        "Copy",
        "Create",
        "Delete",
        "Detach",
        "Drop",
        "Execute",
        "Grant",
        "Insert",
        "Into",
        "LoadData",
        "Lock",
        "Merge",
        "Pragma",
        "Refresh",
        "Rollback",
        "Set",
        "Show",
        "Transaction",
        "TruncateTable",
        "Uncache",
        "Update",
        "Use",
        "Vacuum",
        "With",
    }

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self._forbidden_functions = {item.lower() for item in config.sql_safety.forbidden_functions}
        self._forbidden_schemas = {item.lower() for item in config.sql_safety.forbidden_schemas}

    def evaluate(self, principal: Principal, compiled: CompiledQuery) -> PolicyReport:
        decisions: list[PolicyDecision] = []
        decisions.extend(self._authorize(principal, compiled))
        decisions.extend(self._validate_sql(compiled))
        allowed = not any(decision.outcome == PolicyOutcome.DENY for decision in decisions)
        return PolicyReport(allowed=allowed, decisions=decisions)

    def enforce(self, principal: Principal, compiled: CompiledQuery) -> list[PolicyDecision]:
        report = self.evaluate(principal, compiled)
        if not report.allowed:
            denied = [
                decision.message
                for decision in report.decisions
                if decision.outcome == PolicyOutcome.DENY
            ]
            raise PolicyViolation("; ".join(denied), report.decisions)
        return report.decisions

    def _authorize(self, principal: Principal, compiled: CompiledQuery) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        grants = [self.config.roles[role] for role in principal.roles if role in self.config.roles]
        unknown_roles = [role for role in principal.roles if role not in self.config.roles]
        if unknown_roles:
            decisions.append(
                PolicyDecision(
                    code="auth.unknown_roles",
                    outcome=PolicyOutcome.DENY,
                    message=f"principal has unknown policy roles: {unknown_roles}",
                    evidence={"unknown_roles": unknown_roles},
                )
            )
        if not grants:
            decisions.append(
                PolicyDecision(
                    code="auth.no_grants",
                    outcome=PolicyOutcome.DENY,
                    message="principal has no effective grants",
                )
            )
            return decisions

        metric = compiled.semantic_binding.metric
        if self._allowed_by_any(metric, grants, "allow_metrics"):
            decisions.append(
                PolicyDecision(
                    code="auth.metric_allowed",
                    outcome=PolicyOutcome.ALLOW,
                    message=f"metric {metric} is allowed",
                    evidence={"metric": metric, "roles": principal.roles},
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="auth.metric_denied",
                    outcome=PolicyOutcome.DENY,
                    message=f"metric {metric} is not allowed for principal roles",
                    evidence={"metric": metric, "roles": principal.roles},
                )
            )

        for table in compiled.semantic_binding.source_tables:
            outcome = (
                PolicyOutcome.ALLOW
                if self._allowed_by_any(table, grants, "allow_tables")
                else PolicyOutcome.DENY
            )
            decisions.append(
                PolicyDecision(
                    code=(
                        "auth.table_allowed"
                        if outcome == PolicyOutcome.ALLOW
                        else "auth.table_denied"
                    ),
                    outcome=outcome,
                    message=f"table {table} is {outcome.value}ed",
                    evidence={"table": table},
                )
            )

        deny_patterns = [pattern for grant in grants for pattern in grant.deny_columns]
        for column in compiled.semantic_binding.source_columns:
            if self._matches_any(column, deny_patterns):
                decisions.append(
                    PolicyDecision(
                        code="auth.column_explicitly_denied",
                        outcome=PolicyOutcome.DENY,
                        message=f"column {column} is explicitly denied",
                        evidence={"column": column},
                    )
                )
            elif self._allowed_by_any(column, grants, "allow_columns"):
                decisions.append(
                    PolicyDecision(
                        code="auth.column_allowed",
                        outcome=PolicyOutcome.ALLOW,
                        message=f"column {column} is allowed",
                        evidence={"column": column},
                    )
                )
            else:
                decisions.append(
                    PolicyDecision(
                        code="auth.column_denied",
                        outcome=PolicyOutcome.DENY,
                        message=f"column {column} is not allowed for principal roles",
                        evidence={"column": column},
                    )
                )

        if principal.tenant_id is not None:
            decisions.append(
                PolicyDecision(
                    code="auth.tenant_scoped",
                    outcome=PolicyOutcome.ALLOW,
                    message="principal has an immutable tenant scope",
                    evidence={"tenant_scope_present": True},
                )
            )
        return decisions

    def _validate_sql(self, compiled: CompiledQuery) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        try:
            statements = sqlglot.parse(compiled.sql, read="postgres")
        except sqlglot.errors.ParseError as exc:
            return [
                PolicyDecision(
                    code="sql.parse_failed",
                    outcome=PolicyOutcome.DENY,
                    message=f"SQL parser rejected the statement: {exc}",
                )
            ]

        if len(statements) != 1:
            return [
                PolicyDecision(
                    code="sql.multiple_statements",
                    outcome=PolicyOutcome.DENY,
                    message="exactly one SQL statement is required",
                    evidence={"statement_count": len(statements)},
                )
            ]
        statement = statements[0]
        if statement is None:
            return [
                PolicyDecision(
                    code="sql.empty_statement",
                    outcome=PolicyOutcome.DENY,
                    message="SQL parser returned an empty statement",
                )
            ]
        decisions.append(
            PolicyDecision(
                code="sql.single_statement",
                outcome=PolicyOutcome.ALLOW,
                message="SQL contains exactly one statement",
            )
        )

        if not isinstance(statement, exp.Select):
            decisions.append(
                PolicyDecision(
                    code="sql.not_select",
                    outcome=PolicyOutcome.DENY,
                    message=f"only SELECT is allowed; found {type(statement).__name__}",
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="sql.select_only",
                    outcome=PolicyOutcome.ALLOW,
                    message="statement root is SELECT",
                )
            )

        forbidden_nodes = sorted(
            {
                type(node).__name__
                for node in statement.walk()
                if type(node).__name__ in self.FORBIDDEN_NODE_NAMES
            }
        )
        if forbidden_nodes:
            decisions.append(
                PolicyDecision(
                    code="sql.forbidden_ast_nodes",
                    outcome=PolicyOutcome.DENY,
                    message=f"forbidden SQL operations found: {forbidden_nodes}",
                    evidence={"node_types": forbidden_nodes},
                )
            )

        subqueries = list(statement.find_all(exp.Subquery))
        if subqueries:
            decisions.append(
                PolicyDecision(
                    code="sql.subquery_denied",
                    outcome=PolicyOutcome.DENY,
                    message="subqueries are disabled in the MVP semantic query path",
                    evidence={"count": len(subqueries)},
                )
            )

        stars = list(statement.find_all(exp.Star))
        if self.config.sql_safety.deny_select_star and stars:
            decisions.append(
                PolicyDecision(
                    code="sql.select_star_denied",
                    outcome=PolicyOutcome.DENY,
                    message="SELECT * is forbidden",
                    evidence={"count": len(stars)},
                )
            )
        elif not stars:
            decisions.append(
                PolicyDecision(
                    code="sql.explicit_columns",
                    outcome=PolicyOutcome.ALLOW,
                    message="query uses explicit output expressions",
                )
            )

        actual_tables = sorted(self._table_name(table) for table in statement.find_all(exp.Table))
        expected_tables = sorted(compiled.semantic_binding.source_tables)
        if actual_tables == expected_tables:
            decisions.append(
                PolicyDecision(
                    code="sql.tables_match_binding",
                    outcome=PolicyOutcome.ALLOW,
                    message="AST tables exactly match semantic provenance",
                    evidence={"tables": actual_tables},
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="sql.tables_mismatch_binding",
                    outcome=PolicyOutcome.DENY,
                    message="AST tables differ from semantic provenance",
                    evidence={"actual": actual_tables, "expected": expected_tables},
                )
            )

        for table in statement.find_all(exp.Table):
            schema = table.db
            if self.config.sql_safety.require_schema_qualified_tables and not schema:
                decisions.append(
                    PolicyDecision(
                        code="sql.unqualified_table",
                        outcome=PolicyOutcome.DENY,
                        message=f"table {table.name} is not schema-qualified",
                    )
                )
            if schema and schema.lower() in self._forbidden_schemas:
                decisions.append(
                    PolicyDecision(
                        code="sql.forbidden_schema",
                        outcome=PolicyOutcome.DENY,
                        message=f"schema {schema} is forbidden",
                    )
                )

        alias_to_table = {
            table.alias_or_name: self._table_name(table) for table in statement.find_all(exp.Table)
        }
        actual_physical_columns: set[str] = set()
        unknown_qualifiers: set[str] = set()
        unqualified_columns: set[str] = set()
        output_fields = set(compiled.semantic_binding.output_fields)
        for column in statement.find_all(exp.Column):
            if column.table:
                table_name = alias_to_table.get(column.table)
                if table_name is None:
                    unknown_qualifiers.add(column.table)
                else:
                    actual_physical_columns.add(f"{table_name}.{column.name}")
            elif column.name in output_fields:
                # ORDER BY output aliases are not physical source-column reads.
                continue
            elif len(expected_tables) == 1:
                unqualified_columns.add(column.name)
                actual_physical_columns.add(f"{expected_tables[0]}.{column.name}")
            else:
                unknown_qualifiers.add("<unqualified>")

        expected_physical_columns = set(compiled.semantic_binding.source_columns)
        columns_match = (
            not unknown_qualifiers and actual_physical_columns == expected_physical_columns
        )
        if columns_match:
            decisions.append(
                PolicyDecision(
                    code="sql.columns_match_binding",
                    outcome=PolicyOutcome.ALLOW,
                    message="AST physical columns exactly match semantic provenance",
                    evidence={
                        "columns": sorted(actual_physical_columns),
                        "unqualified_columns": sorted(unqualified_columns),
                    },
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="sql.columns_mismatch_binding",
                    outcome=PolicyOutcome.DENY,
                    message="AST physical columns differ from semantic provenance",
                    evidence={
                        "actual": sorted(actual_physical_columns),
                        "expected": sorted(expected_physical_columns),
                        "missing": sorted(expected_physical_columns - actual_physical_columns),
                        "unexpected": sorted(actual_physical_columns - expected_physical_columns),
                        "unknown_qualifiers": sorted(unknown_qualifiers),
                    },
                )
            )

        forbidden_functions = sorted(
            {
                function_name
                for function_name in self._function_names(statement)
                if function_name in self._forbidden_functions
            }
        )
        if forbidden_functions:
            decisions.append(
                PolicyDecision(
                    code="sql.forbidden_functions",
                    outcome=PolicyOutcome.DENY,
                    message=f"forbidden SQL functions found: {forbidden_functions}",
                    evidence={"functions": forbidden_functions},
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="sql.functions_allowed",
                    outcome=PolicyOutcome.ALLOW,
                    message="no forbidden SQL functions were found",
                )
            )

        placeholders = [int(value) for value in re.findall(r"\$(\d+)\b", compiled.sql)]
        expected_placeholders = list(range(1, len(compiled.parameters) + 1))
        parameter_metadata_matches = sorted(set(placeholders)) == expected_placeholders and len(
            compiled.parameters
        ) == len(compiled.parameter_types)
        decisions.append(
            PolicyDecision(
                code=(
                    "sql.parameters_match"
                    if parameter_metadata_matches
                    else "sql.parameters_mismatch"
                ),
                outcome=(PolicyOutcome.ALLOW if parameter_metadata_matches else PolicyOutcome.DENY),
                message=(
                    "SQL placeholders and parameter metadata are consistent"
                    if parameter_metadata_matches
                    else "SQL placeholders or parameter metadata are inconsistent"
                ),
                evidence={
                    "placeholder_indexes": sorted(set(placeholders)),
                    "parameter_count": len(compiled.parameters),
                    "parameter_type_count": len(compiled.parameter_types),
                },
            )
        )

        normalized_upper = re.sub(r"\s+", " ", compiled.sql.upper())
        if " FOR UPDATE" in normalized_upper or " FOR SHARE" in normalized_upper:
            decisions.append(
                PolicyDecision(
                    code="sql.row_lock_denied",
                    outcome=PolicyOutcome.DENY,
                    message="row-locking SELECT clauses are forbidden",
                )
            )

        limit = statement.args.get("limit")
        limit_value = self._literal_limit(limit)
        if limit_value is None:
            decisions.append(
                PolicyDecision(
                    code="sql.limit_missing_or_dynamic",
                    outcome=PolicyOutcome.DENY,
                    message="query requires a literal LIMIT",
                )
            )
        elif limit_value > self.config.limits.max_rows + 1:
            decisions.append(
                PolicyDecision(
                    code="sql.limit_too_high",
                    outcome=PolicyOutcome.DENY,
                    message=f"query LIMIT {limit_value} exceeds policy guard maximum",
                    evidence={
                        "limit": limit_value,
                        "max_guard_rows": self.config.limits.max_rows + 1,
                    },
                )
            )
        else:
            decisions.append(
                PolicyDecision(
                    code="sql.limit_enforced",
                    outcome=PolicyOutcome.ALLOW,
                    message="query has a policy-compliant literal LIMIT including the truncation sentinel",
                    evidence={"guard_limit": limit_value, "result_limit": limit_value - 1},
                )
            )

        return decisions

    @staticmethod
    def _allowed_by_any(value: str, grants: list[RoleGrant], field: str) -> bool:
        patterns = [pattern for grant in grants for pattern in getattr(grant, field)]
        return PolicyEngine._matches_any(value, patterns)

    @staticmethod
    def _matches_any(value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)

    @staticmethod
    def _table_name(table: exp.Table) -> str:
        schema = table.db
        return f"{schema}.{table.name}" if schema else table.name

    @staticmethod
    def _function_names(statement: exp.Expr) -> set[str]:
        names: set[str] = set()
        for function in statement.find_all(exp.Func):
            if isinstance(function, exp.Anonymous):
                name = function.name
            else:
                try:
                    name = function.sql_name()
                except Exception:  # pragma: no cover - defensive against SQLGlot API drift
                    name = type(function).__name__
            if name:
                names.add(str(name).lower())
        return names

    @staticmethod
    def _literal_limit(limit: Any) -> int | None:
        if limit is None:
            return None
        expression = getattr(limit, "expression", None)
        if isinstance(expression, exp.Literal) and expression.is_int:
            return int(expression.this)
        return None
