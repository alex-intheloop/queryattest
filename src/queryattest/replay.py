from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from queryattest.models import QueryIntent, StrictModel
from queryattest.service import QueryAttestService


class ReplayExpected(StrictModel):
    metric: str
    allowed_tables: list[str] = Field(default_factory=list)
    forbidden_columns: list[str] = Field(default_factory=list)
    max_total_cost: float | None = None
    receipt_status: Literal["verified", "partially_verified", "failed"] | None = None
    first_row: dict[str, Any] = Field(default_factory=dict)
    tolerance_percent: float = Field(default=0.0, ge=0)


class ReplayScenario(StrictModel):
    name: str
    intent: QueryIntent
    expected: ReplayExpected


class ReplayReport(StrictModel):
    name: str
    passed: bool
    stages: list[dict[str, Any]]
    plan_id: str | None = None
    execution_id: str | None = None


def load_scenario(path: Path) -> ReplayScenario:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return ReplayScenario.model_validate(data)


async def run_replay(
    service: QueryAttestService,
    scenario: ReplayScenario,
    *,
    online: bool = False,
    execute: bool = False,
) -> ReplayReport:
    stages: list[dict[str, Any]] = []
    prepared = service.prepare_query(scenario.intent)
    binding = prepared.semantic_binding

    semantic_errors: list[str] = []
    if binding.metric != scenario.expected.metric:
        semantic_errors.append(f"metric mismatch: {binding.metric} != {scenario.expected.metric}")
    if scenario.expected.allowed_tables and not set(binding.source_tables).issubset(
        set(scenario.expected.allowed_tables)
    ):
        semantic_errors.append(
            f"unexpected tables: {sorted(set(binding.source_tables) - set(scenario.expected.allowed_tables))}"
        )
    forbidden_used = sorted(set(binding.source_columns) & set(scenario.expected.forbidden_columns))
    if forbidden_used:
        semantic_errors.append(f"forbidden columns used: {forbidden_used}")
    stages.append(
        {
            "stage": "compile_and_policy",
            "passed": not semantic_errors,
            "errors": semantic_errors,
            "statement_hash": service.store.get_plan(prepared.plan_id).plan.compiled.statement_hash,
        }
    )
    if semantic_errors or not online:
        return ReplayReport(
            name=scenario.name,
            passed=not semantic_errors,
            stages=stages,
            plan_id=prepared.plan_id,
        )

    preflight = await service.preflight_query(prepared.plan_id)
    preflight_errors: list[str] = []
    if (
        scenario.expected.max_total_cost is not None
        and preflight.explain.total_cost > scenario.expected.max_total_cost
    ):
        preflight_errors.append(
            f"cost {preflight.explain.total_cost} exceeds scenario maximum "
            f"{scenario.expected.max_total_cost}"
        )
    stages.append(
        {
            "stage": "preflight",
            "passed": not preflight_errors,
            "errors": preflight_errors,
            "explain": preflight.explain.model_dump(mode="json"),
        }
    )
    if preflight_errors or not execute:
        return ReplayReport(
            name=scenario.name,
            passed=not preflight_errors,
            stages=stages,
            plan_id=prepared.plan_id,
        )

    receipt = await service.execute_approved_query(preflight.ticket)
    result_errors: list[str] = []
    if scenario.expected.receipt_status and receipt.status != scenario.expected.receipt_status:
        result_errors.append(
            f"receipt status {receipt.status} != {scenario.expected.receipt_status}"
        )
    if scenario.expected.first_row:
        if not receipt.answer:
            result_errors.append("expected at least one result row")
        else:
            for field, expected_value in scenario.expected.first_row.items():
                if field not in receipt.answer[0]:
                    result_errors.append(f"first result row is missing field {field}")
                    continue
                actual_value = receipt.answer[0][field]
                if not _values_match(
                    actual_value,
                    expected_value,
                    tolerance_percent=scenario.expected.tolerance_percent,
                ):
                    result_errors.append(
                        f"first_row.{field}: actual={actual_value!r}, expected={expected_value!r}"
                    )
    stages.append(
        {
            "stage": "execute_and_verify",
            "passed": not result_errors,
            "errors": result_errors,
            "receipt_status": receipt.status,
            "row_count": receipt.row_count,
            "result_digest": receipt.provenance.result_digest,
        }
    )
    return ReplayReport(
        name=scenario.name,
        passed=all(stage["passed"] for stage in stages),
        stages=stages,
        plan_id=prepared.plan_id,
        execution_id=receipt.execution_id,
    )


def _values_match(actual: Any, expected: Any, *, tolerance_percent: float) -> bool:
    if actual == expected:
        return True
    try:
        actual_decimal = Decimal(str(actual))
        expected_decimal = Decimal(str(expected))
    except (InvalidOperation, ValueError):
        return False
    if not actual_decimal.is_finite() or not expected_decimal.is_finite():
        return False
    if expected_decimal == 0:
        return actual_decimal == 0
    relative_error = abs(actual_decimal - expected_decimal) / abs(expected_decimal) * 100
    return relative_error <= Decimal(str(tolerance_percent))
