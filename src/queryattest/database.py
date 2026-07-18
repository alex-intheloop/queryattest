from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Protocol

import asyncpg

from queryattest.canonical import json_default
from queryattest.config import PolicyLimits
from queryattest.models import CompiledQuery, ExplainEvidence, Principal


class DatabaseError(RuntimeError):
    public_code = "database_boundary_error"
    public_message = "The database safety boundary rejected or could not complete the operation."


@dataclass(frozen=True)
class DatabaseExecutionResult:
    rows: list[dict[str, Any]]
    truncated: bool
    database_user: str
    database_name: str
    transaction_read_only: bool
    snapshot_time: datetime
    explain: ExplainEvidence


class DatabaseGateway(Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def preflight(
        self,
        compiled: CompiledQuery,
        principal: Principal,
        limits: PolicyLimits,
    ) -> ExplainEvidence: ...

    async def execute(
        self,
        compiled: CompiledQuery,
        principal: Principal,
        *,
        max_rows: int,
        max_total_cost: float,
        max_estimated_rows: int,
        expected_relations: list[str],
        statement_timeout_ms: int,
    ) -> DatabaseExecutionResult: ...


class PostgresGateway:
    """PostgreSQL execution boundary: read-only transaction, RLS context, timeout, cap."""

    def __init__(
        self,
        database_url: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 5,
        application_name: str = "queryattest",
        tenant_guc: str = "app.tenant_id",
    ) -> None:
        self.database_url = database_url
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.application_name = application_name
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", tenant_guc):
            raise ValueError("tenant_guc must be a namespaced PostgreSQL custom setting")
        self.tenant_guc = tenant_guc
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.database_url,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
            server_settings={"application_name": self.application_name},
        )

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def preflight(
        self,
        compiled: CompiledQuery,
        principal: Principal,
        limits: PolicyLimits,
    ) -> ExplainEvidence:
        pool = self._require_pool()
        try:
            async with pool.acquire() as connection:
                async with connection.transaction(readonly=True):
                    await self._set_session_context(
                        connection,
                        principal,
                        statement_timeout_ms=limits.statement_timeout_ms,
                    )
                    (
                        database_user,
                        database_name,
                        transaction_read_only,
                    ) = await self._connection_evidence(connection)
                    return await self._explain_on_connection(
                        connection,
                        compiled,
                        database_user=database_user,
                        database_name=database_name,
                        transaction_read_only=transaction_read_only,
                    )
        except (asyncpg.PostgresError, TimeoutError) as exc:
            raise DatabaseError("PostgreSQL preflight failed") from exc

    async def execute(
        self,
        compiled: CompiledQuery,
        principal: Principal,
        *,
        max_rows: int,
        max_total_cost: float,
        max_estimated_rows: int,
        expected_relations: list[str],
        statement_timeout_ms: int,
    ) -> DatabaseExecutionResult:
        pool = self._require_pool()
        try:
            async with pool.acquire() as connection:
                async with connection.transaction(readonly=True):
                    await self._set_session_context(
                        connection,
                        principal,
                        statement_timeout_ms=statement_timeout_ms,
                    )
                    (
                        database_user,
                        database_name,
                        transaction_read_only,
                    ) = await self._connection_evidence(connection)
                    execution_explain = await self._explain_on_connection(
                        connection,
                        compiled,
                        database_user=database_user,
                        database_name=database_name,
                        transaction_read_only=transaction_read_only,
                    )
                    if not execution_explain.transaction_read_only:
                        raise DatabaseError("execution transaction is not read-only")
                    if execution_explain.total_cost > max_total_cost:
                        raise DatabaseError(
                            "execution-time EXPLAIN cost exceeds the signed ticket cap"
                        )
                    if execution_explain.plan_rows > max_estimated_rows:
                        raise DatabaseError("execution-time EXPLAIN row estimate exceeds policy")
                    if set(execution_explain.relation_names) != set(expected_relations):
                        raise DatabaseError(
                            "execution-time EXPLAIN relations differ from semantic provenance"
                        )
                    snapshot_time = await connection.fetchval("SELECT transaction_timestamp()")
                    records = await connection.fetch(compiled.sql, *compiled.parameters)
        except DatabaseError:
            raise
        except (asyncpg.PostgresError, TimeoutError) as exc:
            raise DatabaseError("PostgreSQL execution failed") from exc

        if len(records) > max_rows + 1:
            raise DatabaseError("database returned more rows than the compiled sentinel limit")
        truncated = len(records) > max_rows
        selected = records[:max_rows]
        rows = [self._json_safe_record(record) for record in selected]
        return DatabaseExecutionResult(
            rows=rows,
            truncated=truncated,
            database_user=database_user,
            database_name=database_name,
            transaction_read_only=transaction_read_only,
            snapshot_time=snapshot_time,
            explain=execution_explain,
        )

    async def doctor(self) -> dict[str, Any]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            database_user = await connection.fetchval("SELECT current_user")
            database_name = await connection.fetchval("SELECT current_database()")
            server_version = await connection.fetchval("SHOW server_version")
            default_read_only = await connection.fetchval(
                "SELECT current_setting('default_transaction_read_only')"
            )
            role = await connection.fetchrow(
                """
                SELECT
                    rolsuper,
                    rolcreaterole,
                    rolcreatedb,
                    rolreplication,
                    rolbypassrls
                FROM pg_roles
                WHERE rolname = current_user
                """
            )
            ssl_enabled = await connection.fetchval(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            )

        if role is None:
            raise DatabaseError("could not inspect the current PostgreSQL role")
        warnings: list[str] = []
        if default_read_only != "on":
            warnings.append("database role default_transaction_read_only is not on")
        role_flags = {
            "superuser": bool(role["rolsuper"]),
            "create_role": bool(role["rolcreaterole"]),
            "create_database": bool(role["rolcreatedb"]),
            "replication": bool(role["rolreplication"]),
            "bypass_rls": bool(role["rolbypassrls"]),
        }
        enabled_privileged_flags = [name for name, enabled in role_flags.items() if enabled]
        if enabled_privileged_flags:
            warnings.append(
                "database role has privileged flags: " + ", ".join(enabled_privileged_flags)
            )
        if not ssl_enabled:
            warnings.append(
                "database connection is not using TLS; acceptable only for an isolated local demo"
            )

        return {
            "database_user": database_user,
            "database_name": database_name,
            "server_version": server_version,
            "default_transaction_read_only": default_read_only,
            "role_flags": role_flags,
            "connection_tls": bool(ssl_enabled),
            "safe_role_defaults": (default_read_only == "on" and not enabled_privileged_flags),
            "warnings": warnings,
        }

    async def _explain_on_connection(
        self,
        connection: asyncpg.Connection,
        compiled: CompiledQuery,
        *,
        database_user: str,
        database_name: str,
        transaction_read_only: bool,
    ) -> ExplainEvidence:
        # PostgreSQL omits schema names from non-verbose JSON plans. Keep them
        # so EXPLAIN relations can be reconciled with schema-qualified semantic
        # provenance instead of reducing `analytics.orders` to `orders`.
        explain_sql = f"EXPLAIN (FORMAT JSON, COSTS TRUE, VERBOSE TRUE) {compiled.sql}"
        raw_plan = await connection.fetchval(explain_sql, *compiled.parameters)
        plan_document = self._decode_explain(raw_plan)
        root = plan_document[0]["Plan"]
        return ExplainEvidence(
            total_cost=float(root.get("Total Cost", 0.0)),
            plan_rows=self._max_plan_rows(root),
            plan_width=(int(root["Plan Width"]) if "Plan Width" in root else None),
            node_type=str(root.get("Node Type", "Unknown")),
            relation_names=sorted(self._collect_relations(root)),
            database_user=database_user,
            database_name=database_name,
            transaction_read_only=transaction_read_only,
        )

    async def _set_session_context(
        self,
        connection: asyncpg.Connection,
        principal: Principal,
        *,
        statement_timeout_ms: int,
    ) -> None:
        await connection.execute("SET LOCAL row_security = on")
        await connection.fetchval(
            "SELECT set_config('statement_timeout', $1, true)",
            f"{statement_timeout_ms}ms",
        )
        if principal.tenant_id is not None:
            await connection.fetchval(
                "SELECT set_config($1, $2, true)",
                self.tenant_guc,
                principal.tenant_id,
            )

    @staticmethod
    async def _connection_evidence(
        connection: asyncpg.Connection,
    ) -> tuple[str, str, bool]:
        row = await connection.fetchrow(
            """
            SELECT
                current_user AS database_user,
                current_database() AS database_name,
                current_setting('transaction_read_only') = 'on' AS transaction_read_only
            """
        )
        if row is None:
            raise DatabaseError("PostgreSQL returned no connection evidence")
        return (
            str(row["database_user"]),
            str(row["database_name"]),
            bool(row["transaction_read_only"]),
        )

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise DatabaseError("database pool has not been started")
        return self._pool

    @staticmethod
    def _decode_explain(raw_plan: Any) -> list[dict[str, Any]]:
        try:
            decoded = json.loads(raw_plan) if isinstance(raw_plan, str) else raw_plan
        except (json.JSONDecodeError, TypeError) as exc:
            raise DatabaseError("PostgreSQL returned malformed EXPLAIN JSON") from exc
        if (
            not isinstance(decoded, list)
            or not decoded
            or not isinstance(decoded[0], dict)
            or not isinstance(decoded[0].get("Plan"), dict)
        ):
            raise DatabaseError("PostgreSQL returned an unexpected EXPLAIN JSON document")
        return decoded

    @classmethod
    def _collect_relations(cls, node: Mapping[str, Any]) -> set[str]:
        relations: set[str] = set()
        schema = node.get("Schema")
        relation = node.get("Relation Name")
        if relation:
            relations.add(f"{schema}.{relation}" if schema else str(relation))
        for child in node.get("Plans", []) or []:
            if isinstance(child, Mapping):
                relations.update(cls._collect_relations(child))
        return relations

    @classmethod
    def _max_plan_rows(cls, node: Mapping[str, Any]) -> int:
        maximum = int(node.get("Plan Rows", 0))
        for child in node.get("Plans", []) or []:
            if isinstance(child, Mapping):
                maximum = max(maximum, cls._max_plan_rows(child))
        return maximum

    @classmethod
    def _json_safe_record(cls, record: Mapping[str, Any]) -> dict[str, Any]:
        return {str(key): cls._json_safe_value(value) for key, value in record.items()}

    @classmethod
    def _json_safe_value(cls, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, bool)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise DatabaseError("database returned a non-finite floating-point value")
            return value
        if isinstance(value, Decimal):
            if not value.is_finite():
                raise DatabaseError("database returned a non-finite decimal value")
            return str(value)
        if isinstance(value, Mapping):
            return {str(key): cls._json_safe_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._json_safe_value(item) for item in value]
        try:
            return json_default(value)
        except TypeError:
            return str(value)
