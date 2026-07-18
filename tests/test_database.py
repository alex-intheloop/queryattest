from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest

from queryattest.config import PolicyLimits
from queryattest.database import DatabaseError, PostgresGateway
from queryattest.models import QueryIntent


class AsyncContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None


class FakeConnection:
    def __init__(
        self,
        *,
        plan: dict[str, Any] | None = None,
        records: list[dict[str, Any]] | None = None,
        read_only: bool = True,
        database_user: str = "queryattest_reader",
        database_name: str = "queryattest",
    ) -> None:
        self.plan = plan or {
            "Plan": {
                "Node Type": "Aggregate",
                "Total Cost": 12.5,
                "Plan Rows": 2,
                "Plan Width": 16,
                "Plans": [
                    {
                        "Node Type": "Seq Scan",
                        "Schema": "analytics",
                        "Relation Name": "orders",
                        "Plan Rows": 25,
                    }
                ],
            }
        }
        self.records = records or []
        self.read_only = read_only
        self.database_user = database_user
        self.database_name = database_name
        self.commands: list[tuple[str, tuple[Any, ...]]] = []
        self.readonly_transaction_requested = False
        self.snapshot = datetime(2026, 7, 18, 1, 2, 3, tzinfo=UTC)

    def transaction(self, *, readonly: bool) -> AsyncContext:
        self.readonly_transaction_requested = readonly
        return AsyncContext(self)

    async def execute(self, sql: str, *parameters: Any) -> str:
        self.commands.append((sql, parameters))
        return "SET"

    async def fetchval(self, sql: str, *parameters: Any) -> Any:
        self.commands.append((sql, parameters))
        if sql.startswith("EXPLAIN"):
            return [self.plan]
        if sql == "SELECT transaction_timestamp()":
            return self.snapshot
        if "set_config" in sql:
            return parameters[-1]
        raise AssertionError(f"unexpected fetchval SQL: {sql}")

    async def fetchrow(self, sql: str, *parameters: Any) -> dict[str, Any]:
        self.commands.append((sql, parameters))
        return {
            "database_user": self.database_user,
            "database_name": self.database_name,
            "transaction_read_only": self.read_only,
        }

    async def fetch(self, sql: str, *parameters: Any) -> list[dict[str, Any]]:
        self.commands.append((sql, parameters))
        return self.records


class FakePool:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.closed = False

    def acquire(self) -> AsyncContext:
        return AsyncContext(self.connection)

    async def close(self) -> None:
        self.closed = True


def compiled_query(service: Any):
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    return service.store.get_plan(prepared.plan_id).plan.compiled


def gateway_with(connection: FakeConnection) -> PostgresGateway:
    gateway = PostgresGateway("postgresql://unused")
    gateway._pool = FakePool(connection)  # type: ignore[assignment]
    return gateway


def test_tenant_guc_must_be_namespaced() -> None:
    with pytest.raises(ValueError, match="namespaced"):
        PostgresGateway("postgresql://unused", tenant_guc="tenant_id")


def test_gateway_requires_started_pool() -> None:
    gateway = PostgresGateway("postgresql://unused")
    with pytest.raises(DatabaseError, match="not been started"):
        gateway._require_pool()


@pytest.mark.asyncio
async def test_preflight_sets_context_and_returns_database_evidence(service: Any) -> None:
    connection = FakeConnection()
    gateway = gateway_with(connection)

    evidence = await gateway.preflight(
        compiled_query(service), service.principals.current(), PolicyLimits()
    )

    assert connection.readonly_transaction_requested
    assert evidence.database_user == "queryattest_reader"
    assert evidence.database_name == "queryattest"
    assert evidence.transaction_read_only
    assert evidence.relation_names == ["analytics.orders"]
    assert evidence.plan_rows == 25
    assert any(
        sql.startswith("EXPLAIN (FORMAT JSON, COSTS TRUE, VERBOSE TRUE)")
        for sql, _ in connection.commands
    )
    assert any(sql == "SET LOCAL row_security = on" for sql, _ in connection.commands)
    assert any(
        sql == "SELECT set_config($1, $2, true)" and parameters == ("app.tenant_id", "tenant-a")
        for sql, parameters in connection.commands
    )


@pytest.mark.asyncio
async def test_execute_truncates_only_the_sentinel_row(service: Any) -> None:
    connection = FakeConnection(
        records=[{"net_revenue": Decimal("10.00")}, {"net_revenue": Decimal("20.00")}]
    )
    gateway = gateway_with(connection)
    compiled = compiled_query(service)

    result = await gateway.execute(
        compiled,
        service.principals.current(),
        max_rows=1,
        max_total_cost=100,
        max_estimated_rows=100,
        expected_relations=["analytics.orders"],
        statement_timeout_ms=5_000,
    )

    assert result.rows == [{"net_revenue": "10.00"}]
    assert result.truncated
    assert result.snapshot_time == connection.snapshot
    assert connection.readonly_transaction_requested


@pytest.mark.asyncio
async def test_execute_rejects_more_than_one_sentinel_row(service: Any) -> None:
    connection = FakeConnection(records=[{"x": 1}, {"x": 2}, {"x": 3}])
    gateway = gateway_with(connection)

    with pytest.raises(DatabaseError, match="sentinel"):
        await gateway.execute(
            compiled_query(service),
            service.principals.current(),
            max_rows=1,
            max_total_cost=100,
            max_estimated_rows=100,
            expected_relations=["analytics.orders"],
            statement_timeout_ms=5_000,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("plan_update", "read_only", "expected_message"),
    [
        ({"Total Cost": 101}, True, "cost exceeds"),
        ({"Plan Rows": 101, "Plans": []}, True, "row estimate exceeds"),
        ({"Plans": [{"Schema": "analytics", "Relation Name": "other"}]}, True, "relations differ"),
        ({}, False, "not read-only"),
    ],
)
async def test_execute_rechecks_safety_guards(
    service: Any,
    plan_update: dict[str, Any],
    read_only: bool,
    expected_message: str,
) -> None:
    root = {
        "Node Type": "Aggregate",
        "Total Cost": 10,
        "Plan Rows": 10,
        "Plans": [{"Schema": "analytics", "Relation Name": "orders", "Plan Rows": 10}],
    }
    root.update(plan_update)
    connection = FakeConnection(plan={"Plan": root}, read_only=read_only)
    gateway = gateway_with(connection)

    with pytest.raises(DatabaseError, match=expected_message):
        await gateway.execute(
            compiled_query(service),
            service.principals.current(),
            max_rows=10,
            max_total_cost=100,
            max_estimated_rows=100,
            expected_relations=["analytics.orders"],
            statement_timeout_ms=5_000,
        )


def test_explain_decoder_rejects_malformed_documents() -> None:
    assert (
        PostgresGateway._decode_explain('[{"Plan":{"Node Type":"Result"}}]')[0]["Plan"]["Node Type"]
        == "Result"
    )

    with pytest.raises(DatabaseError, match="malformed"):
        PostgresGateway._decode_explain("not-json")
    with pytest.raises(DatabaseError, match="unexpected"):
        PostgresGateway._decode_explain({"Plan": {}})


def test_plan_helpers_walk_nested_nodes() -> None:
    plan = {
        "Plan Rows": 2,
        "Plans": [
            {
                "Schema": "analytics",
                "Relation Name": "orders",
                "Plan Rows": 20,
                "Plans": [
                    {
                        "Schema": "analytics",
                        "Relation Name": "customers",
                        "Plan Rows": 5,
                    }
                ],
            }
        ],
    }
    assert PostgresGateway._collect_relations(plan) == {
        "analytics.orders",
        "analytics.customers",
    }
    assert PostgresGateway._max_plan_rows(plan) == 20


def test_json_safe_conversion_is_deterministic() -> None:
    value = {
        "amount": Decimal("12.30"),
        "date": date(2026, 7, 18),
        "id": UUID("12345678-1234-5678-1234-567812345678"),
        "bytes": b"abc",
        "nested": (Decimal("1.5"),),
    }
    assert PostgresGateway._json_safe_value(value) == {
        "amount": "12.30",
        "date": "2026-07-18",
        "id": "12345678-1234-5678-1234-567812345678",
        "bytes": {"$bytes_hex": "616263"},
        "nested": ["1.5"],
    }


@pytest.mark.parametrize("value", [float("nan"), float("inf"), Decimal("Infinity")])
def test_json_safe_conversion_rejects_non_finite_numbers(value: Any) -> None:
    with pytest.raises(DatabaseError, match="non-finite"):
        PostgresGateway._json_safe_value(value)
