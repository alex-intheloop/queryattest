from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

import sqlglot
from sqlglot import exp

from queryattest.canonical import sha256_json
from queryattest.config import (
    DataProductDefinition,
    FieldDefinition,
    MetricDefinition,
    SemanticConfig,
)
from queryattest.models import (
    CompiledQuery,
    FilterOperator,
    FilterSpec,
    Principal,
    QueryIntent,
    SemanticBinding,
)


class SemanticError(ValueError):
    """Raised when a structured intent cannot be compiled safely."""


def _render_expression(template: str, alias: str) -> str:
    if ";" in template:
        raise SemanticError("semantic SQL expressions may not contain semicolons")
    if any(marker in template for marker in ("--", "/*", "*/")):
        raise SemanticError("semantic SQL expressions may not contain comments")
    if re.search(r"\$\d+\b|\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", template):
        raise SemanticError(
            "semantic SQL expressions may not contain bind parameters or dollar quoting"
        )
    rendered = template.replace("{alias}", alias)
    if "{" in rendered or "}" in rendered:
        raise SemanticError("semantic SQL expressions contain an unknown template placeholder")
    return rendered


def _parse_scalar_expression(label: str, rendered: str) -> exp.Expr:
    try:
        expressions = sqlglot.parse(rendered, read="postgres")
    except sqlglot.errors.ParseError as exc:
        raise SemanticError(f"invalid {label} expression: {exc}") from exc
    if len(expressions) != 1 or expressions[0] is None:
        raise SemanticError(f"{label} must compile into exactly one SQL expression")
    expression = expressions[0]
    if isinstance(expression, (exp.Select, exp.Subquery)):
        raise SemanticError(f"{label} must be a scalar SQL expression")
    return expression


def _parameter(index: int) -> exp.Parameter:
    return exp.Parameter(this=exp.Literal.number(index))


def _parameter_type(field: FieldDefinition) -> str:
    return field.data_type


class SemanticCatalog:
    """Compile versioned business metrics into parameterized PostgreSQL SELECTs."""

    def __init__(self, config: SemanticConfig) -> None:
        self.config = config
        self._validate_expressions()

    def list_metrics(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for name, metric in sorted(self.config.metrics.items()):
            product = self.config.data_products[metric.data_product]
            result.append(
                {
                    "name": name,
                    "version": metric.version,
                    "description": metric.description,
                    "unit": metric.unit,
                    "data_product": metric.data_product,
                    "dimensions": sorted(
                        field_name
                        for field_name, field in product.fields.items()
                        if field.groupable
                    ),
                    "filter_fields": sorted(
                        field_name
                        for field_name, field in product.fields.items()
                        if field.filterable
                    ),
                }
            )
        return result

    def describe_metric(self, metric_name: str) -> dict[str, Any]:
        metric, product = self._resolve(metric_name)
        return {
            "name": metric_name,
            "version": metric.version,
            "description": metric.description,
            "unit": metric.unit,
            "output_name": metric.output_name,
            "data_product": metric.data_product,
            "source_table": product.table,
            "dimensions": {
                name: {
                    "data_type": field.data_type,
                    "description": field.description,
                    "filterable": field.filterable,
                }
                for name, field in product.fields.items()
                if field.groupable
            },
            "filter_fields": {
                name: {
                    "data_type": field.data_type,
                    "description": field.description,
                }
                for name, field in product.fields.items()
                if field.filterable
            },
            "checks": [check.model_dump(mode="json") for check in metric.checks],
        }

    def compile(
        self,
        intent: QueryIntent,
        principal: Principal,
        *,
        max_rows: int,
        max_parameters: int = 500,
    ) -> CompiledQuery:
        metric, product = self._resolve(intent.metric)
        alias = product.alias

        dimensions = self._validate_dimensions(intent.dimensions, product)
        self._validate_order_by(intent, metric, dimensions)

        select_expressions: list[exp.Expr] = []
        group_expressions: list[exp.Expr] = []
        source_columns: set[str] = set()

        for name, field in dimensions:
            rendered = _render_expression(field.expression, alias)
            expression = _parse_scalar_expression(f"dimension {name}", rendered)
            select_expressions.append(exp.alias_(expression.copy(), name, quoted=True))
            group_expressions.append(expression.copy())
            source_columns.update(f"{product.table}.{column}" for column in field.columns)

        metric_expression = _parse_scalar_expression(
            f"metric {intent.metric}", _render_expression(metric.expression, alias)
        )
        select_expressions.append(exp.alias_(metric_expression, metric.output_name, quoted=True))
        source_columns.update(f"{product.table}.{column}" for column in metric.columns)
        source_columns.update(f"{product.table}.{column}" for column in metric.base_filter_columns)

        where_expressions = [
            _parse_scalar_expression(
                f"metric {intent.metric} base filter",
                _render_expression(base_filter, alias),
            )
            for base_filter in metric.base_filters
        ]
        parameters: list[Any] = []
        parameter_types: list[str] = []

        if product.tenant_column:
            if principal.tenant_id is None:
                raise SemanticError(
                    f"data product {metric.data_product} requires a tenant-scoped principal"
                )
            parameters.append(principal.tenant_id)
            parameter_types.append("string")
            where_expressions.append(
                exp.EQ(
                    this=exp.column(product.tenant_column, table=alias),
                    expression=_parameter(len(parameters)),
                )
            )
            source_columns.add(f"{product.table}.{product.tenant_column}")

        for filter_spec in intent.filters:
            predicate, values, value_types, columns = self._compile_filter(
                filter_spec,
                product,
                start_index=len(parameters) + 1,
            )
            where_expressions.append(predicate)
            parameters.extend(values)
            parameter_types.extend(value_types)
            source_columns.update(f"{product.table}.{column}" for column in columns)
            if len(parameters) > max_parameters:
                raise SemanticError(
                    f"query requires {len(parameters)} bind parameters; maximum is {max_parameters}"
                )

        effective_limit = min(intent.limit, max_rows)
        schema_name, table_name = product.table.split(".", maxsplit=1)
        table = exp.Table(
            this=exp.to_identifier(table_name),
            db=exp.to_identifier(schema_name),
        ).as_(alias)
        statement = exp.select(*select_expressions).from_(table)
        if where_expressions:
            combined_predicate = where_expressions[0]
            for predicate in where_expressions[1:]:
                combined_predicate = exp.and_(combined_predicate, predicate)
            statement = statement.where(combined_predicate)
        if group_expressions:
            statement = statement.group_by(*group_expressions)
        if intent.order_by:
            order_expressions = [
                exp.Ordered(
                    this=exp.Column(this=exp.to_identifier(sort.field, quoted=True)),
                    desc=sort.direction.value == "desc",
                    # Preserve PostgreSQL's implicit NULL ordering without adding a clause.
                    nulls_first=sort.direction.value == "desc",
                )
                for sort in intent.order_by
            ]
            statement = statement.order_by(*order_expressions)
        statement = statement.limit(effective_limit + 1)
        normalized_sql = statement.sql(dialect="postgres", pretty=False)

        binding = SemanticBinding(
            metric=intent.metric,
            metric_version=metric.version,
            data_product=metric.data_product,
            dimensions=[name for name, _ in dimensions],
            filters=[filter_spec.field for filter_spec in intent.filters],
            source_tables=[product.table],
            source_columns=sorted(source_columns),
            output_fields=[name for name, _ in dimensions] + [metric.output_name],
            semantic_catalog_version=self.config.version,
        )
        statement_hash = sha256_json(
            {
                "sql": normalized_sql,
                "parameters": parameters,
                "parameter_types": parameter_types,
                "semantic_binding": binding.model_dump(mode="json"),
            }
        )
        return CompiledQuery(
            sql=normalized_sql,
            parameters=parameters,
            parameter_types=parameter_types,
            statement_hash=statement_hash,
            semantic_binding=binding,
        )

    def metric_definition(self, metric_name: str) -> MetricDefinition:
        metric, _ = self._resolve(metric_name)
        return metric

    def _resolve(self, metric_name: str) -> tuple[MetricDefinition, DataProductDefinition]:
        try:
            metric = self.config.metrics[metric_name]
        except KeyError as exc:
            raise SemanticError(f"unknown metric: {metric_name}") from exc
        product = self.config.data_products[metric.data_product]
        return metric, product

    def _validate_dimensions(
        self, dimension_names: Iterable[str], product: DataProductDefinition
    ) -> list[tuple[str, FieldDefinition]]:
        seen: set[str] = set()
        dimensions: list[tuple[str, FieldDefinition]] = []
        for name in dimension_names:
            if name in seen:
                raise SemanticError(f"duplicate dimension: {name}")
            seen.add(name)
            try:
                field = product.fields[name]
            except KeyError as exc:
                raise SemanticError(f"unknown dimension: {name}") from exc
            if not field.groupable:
                raise SemanticError(f"field is not groupable: {name}")
            dimensions.append((name, field))
        return dimensions

    @staticmethod
    def _validate_order_by(
        intent: QueryIntent,
        metric: MetricDefinition,
        dimensions: list[tuple[str, FieldDefinition]],
    ) -> None:
        dimension_names = [name for name, _ in dimensions]
        if metric.output_name in dimension_names:
            raise SemanticError(
                f"dimension {metric.output_name!r} conflicts with the metric output name"
            )
        allowed = set(dimension_names) | {metric.output_name}
        seen: set[str] = set()
        for sort in intent.order_by:
            if sort.field not in allowed:
                raise SemanticError(
                    f"order_by field {sort.field!r} must be a selected dimension or {metric.output_name!r}"
                )
            if sort.field in seen:
                raise SemanticError(f"duplicate order_by field: {sort.field}")
            seen.add(sort.field)

    def _compile_filter(
        self,
        filter_spec: FilterSpec,
        product: DataProductDefinition,
        *,
        start_index: int,
    ) -> tuple[exp.Expr, list[Any], list[str], list[str]]:
        try:
            field = product.fields[filter_spec.field]
        except KeyError as exc:
            raise SemanticError(f"unknown filter field: {filter_spec.field}") from exc
        if not field.filterable:
            raise SemanticError(f"field is not filterable: {filter_spec.field}")

        expression = _parse_scalar_expression(
            f"filter field {filter_spec.field}",
            _render_expression(field.expression, product.alias),
        )
        op = filter_spec.op
        values: list[Any] = []
        parameter_types: list[str] = []

        if op == FilterOperator.IS_NULL:
            predicate: exp.Expr = exp.Is(this=expression, expression=exp.Null())
        elif op == FilterOperator.NOT_NULL:
            predicate = exp.Not(this=exp.Is(this=expression, expression=exp.Null()))
        elif op in {FilterOperator.IN, FilterOperator.NOT_IN}:
            if not isinstance(filter_spec.value, list):
                raise SemanticError(f"operator {op} requires a list value")
            values = [self._coerce_value(field, value) for value in filter_spec.value]
            parameter_types = [_parameter_type(field)] * len(values)
            predicate = exp.In(
                this=expression,
                expressions=[
                    _parameter(index) for index in range(start_index, start_index + len(values))
                ],
            )
            if op == FilterOperator.NOT_IN:
                predicate = exp.Not(this=predicate)
        elif op == FilterOperator.BETWEEN:
            if not isinstance(filter_spec.value, list):
                raise SemanticError("between requires a list value")
            values = [self._coerce_value(field, value) for value in filter_spec.value]
            parameter_types = [_parameter_type(field), _parameter_type(field)]
            predicate = exp.Between(
                this=expression,
                low=_parameter(start_index),
                high=_parameter(start_index + 1),
            )
        else:
            operator_type: type[exp.Binary] = {
                FilterOperator.EQ: exp.EQ,
                FilterOperator.NEQ: exp.NEQ,
                FilterOperator.GT: exp.GT,
                FilterOperator.GTE: exp.GTE,
                FilterOperator.LT: exp.LT,
                FilterOperator.LTE: exp.LTE,
            }[op]
            values = [self._coerce_value(field, filter_spec.value)]
            parameter_types = [_parameter_type(field)]
            predicate = operator_type(this=expression, expression=_parameter(start_index))

        return predicate, values, parameter_types, field.columns

    @staticmethod
    def _coerce_value(field: FieldDefinition, value: Any) -> Any:
        if value is None:
            raise SemanticError("null filter values require the is_null or not_null operator")
        data_type = field.data_type
        try:
            if data_type == "string":
                if not isinstance(value, str):
                    raise TypeError("expected a string")
                return value
            if data_type == "integer":
                if isinstance(value, bool):
                    raise TypeError("boolean is not an integer filter value")
                if isinstance(value, int):
                    return value
                if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value):
                    return int(value)
                raise TypeError("expected an integer or canonical integer string")
            if data_type == "number":
                if isinstance(value, bool):
                    raise TypeError("boolean is not a numeric filter value")
                converted = Decimal(str(value))
                if not converted.is_finite():
                    raise ValueError("numeric filter values must be finite")
                return converted
            if data_type == "boolean":
                if isinstance(value, bool):
                    return value
                if isinstance(value, str) and value.lower() in {"true", "false"}:
                    return value.lower() == "true"
                raise TypeError("expected a boolean")
            if data_type == "date":
                if isinstance(value, datetime):
                    return value.date()
                if isinstance(value, date):
                    return value
                return date.fromisoformat(str(value))
            if data_type == "timestamp":
                if isinstance(value, datetime):
                    converted_timestamp = value
                else:
                    rendered = str(value).replace("Z", "+00:00")
                    converted_timestamp = datetime.fromisoformat(rendered)
                if converted_timestamp.tzinfo is None or converted_timestamp.utcoffset() is None:
                    raise SemanticError("timestamp filter values must include a UTC offset")
                return converted_timestamp
            if data_type == "uuid":
                if isinstance(value, UUID):
                    return value
                return UUID(str(value))
        except SemanticError:
            raise
        except (TypeError, ValueError, InvalidOperation) as exc:
            raise SemanticError(f"invalid {data_type} value for filter field") from exc
        raise SemanticError(f"unsupported semantic data type: {data_type}")

    def _validate_expressions(self) -> None:
        """Prove trusted semantic expressions match their declared physical provenance."""
        for product_name, product in self.config.data_products.items():
            for field_name, field in product.fields.items():
                actual = self._expression_columns(
                    f"field {product_name}.{field_name}", field.expression, product
                )
                expected = set(field.columns)
                if actual != expected:
                    raise SemanticError(
                        f"field {product_name}.{field_name} provenance mismatch; "
                        f"declared={sorted(expected)}, parsed={sorted(actual)}"
                    )

            for metric_name, metric in self.config.metrics.items():
                if metric.data_product != product_name:
                    continue
                metric_columns = self._expression_columns(
                    f"metric {metric_name}", metric.expression, product
                )
                expected_metric_columns = set(metric.columns)
                if metric_columns != expected_metric_columns:
                    raise SemanticError(
                        f"metric {metric_name} provenance mismatch; "
                        f"declared={sorted(expected_metric_columns)}, "
                        f"parsed={sorted(metric_columns)}"
                    )

                parsed_base_filter_columns: set[str] = set()
                for index, base_filter in enumerate(metric.base_filters):
                    parsed_base_filter_columns.update(
                        self._expression_columns(
                            f"metric {metric_name} base_filter[{index}]",
                            base_filter,
                            product,
                        )
                    )
                expected_base_filter_columns = set(metric.base_filter_columns)
                if parsed_base_filter_columns != expected_base_filter_columns:
                    raise SemanticError(
                        f"metric {metric_name} base-filter provenance mismatch; "
                        f"declared={sorted(expected_base_filter_columns)}, "
                        f"parsed={sorted(parsed_base_filter_columns)}"
                    )

    def _expression_columns(
        self,
        label: str,
        expression: str,
        product: DataProductDefinition,
    ) -> set[str]:
        rendered = _render_expression(expression, product.alias)
        parsed_expression = _parse_scalar_expression(label, rendered)

        schema_name, table_name = product.table.split(".", maxsplit=1)
        trusted_table = exp.Table(
            this=exp.to_identifier(table_name),
            db=exp.to_identifier(schema_name),
        ).as_(product.alias)
        statement = exp.select(parsed_expression).from_(trusted_table)

        tables = {self._table_name(table) for table in statement.find_all(exp.Table)}
        if tables != {product.table}:
            raise SemanticError(
                f"{label} may reference only {product.table}; found {sorted(tables)}"
            )
        if list(statement.find_all(exp.Star)):
            raise SemanticError(f"{label} may not contain a star expression")
        if list(statement.find_all(exp.Subquery)) or statement.args.get("with") is not None:
            raise SemanticError(f"{label} may not contain subqueries or common table expressions")

        columns: set[str] = set()
        for column in statement.find_all(exp.Column):
            if column.table != product.alias:
                rendered_column = column.sql(dialect="postgres")
                raise SemanticError(
                    f"{label} column {rendered_column} must be qualified by alias {product.alias}"
                )
            columns.add(column.name)
        return columns

    @staticmethod
    def _table_name(table: exp.Table) -> str:
        schema = table.db
        return f"{schema}.{table.name}" if schema else table.name
