from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from queryattest.app import create_service
from queryattest.config import AppSettings, PolicyLimits
from queryattest.database import DatabaseExecutionResult
from queryattest.models import CompiledQuery, ExplainEvidence, Principal

ROOT = Path(__file__).resolve().parents[1]
TEST_SECRET = "unit-test-secret-0123456789abcdef-0123456789abcdef"


class FakeDatabase:
    def __init__(
        self,
        *,
        rows: list[dict[str, Any]] | None = None,
        total_cost: float = 12.5,
        plan_rows: int = 10,
        read_only: bool = True,
    ) -> None:
        self.rows = rows or [{"net_revenue": "2000000.00"}]
        self.total_cost = total_cost
        self.plan_rows = plan_rows
        self.read_only = read_only
        self.execution_total_cost: float | None = None
        self.execution_plan_rows: int | None = None
        self.execution_relations: list[str] | None = None
        self.execution_database_user: str = "queryattest_reader"
        self.execution_database_name: str = "queryattest"
        self.ignore_row_cap = False
        self.started = False
        self.executions = 0

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.started = False

    async def preflight(
        self,
        compiled: CompiledQuery,
        principal: Principal,
        limits: PolicyLimits,
    ) -> ExplainEvidence:
        return ExplainEvidence(
            total_cost=self.total_cost,
            plan_rows=self.plan_rows,
            plan_width=32,
            node_type="Aggregate",
            relation_names=compiled.semantic_binding.source_tables,
            database_user="queryattest_reader",
            database_name="queryattest",
            transaction_read_only=self.read_only,
        )

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
        self.executions += 1
        truncated = len(self.rows) > max_rows
        returned_rows = self.rows if self.ignore_row_cap else self.rows[:max_rows]
        return DatabaseExecutionResult(
            rows=returned_rows,
            truncated=truncated,
            database_user=self.execution_database_user,
            database_name=self.execution_database_name,
            transaction_read_only=self.read_only,
            snapshot_time=datetime(2026, 7, 16, 9, 0, tzinfo=UTC),
            explain=ExplainEvidence(
                total_cost=(
                    self.execution_total_cost
                    if self.execution_total_cost is not None
                    else self.total_cost
                ),
                plan_rows=(
                    self.execution_plan_rows
                    if self.execution_plan_rows is not None
                    else self.plan_rows
                ),
                plan_width=32,
                node_type="Aggregate",
                relation_names=self.execution_relations or expected_relations,
                database_user=self.execution_database_user,
                database_name=self.execution_database_name,
                transaction_read_only=self.read_only,
            ),
        )


@pytest.fixture
def settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        database_url="postgresql://unused",
        policy_path=ROOT / "config" / "policy.yaml",
        semantics_path=ROOT / "config" / "semantics.yaml",
        state_path=tmp_path / "state.db",
        ticket_secret=TEST_SECRET,
        user_id="alex",
        roles="finance_analyst",
        tenant_id="tenant-a",
    )


@pytest.fixture
def fake_database() -> FakeDatabase:
    return FakeDatabase()


@pytest.fixture
def service(settings: AppSettings, fake_database: FakeDatabase):
    instance = create_service(settings)
    instance.database = fake_database
    return instance
