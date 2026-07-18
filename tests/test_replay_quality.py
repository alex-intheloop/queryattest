from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from queryattest.models import QueryIntent
from queryattest.replay import (
    ReplayExpected,
    ReplayScenario,
    _values_match,
    load_scenario,
    run_replay,
)


def scenario(**expected_updates: Any) -> ReplayScenario:
    expected = {
        "metric": "net_revenue",
        "allowed_tables": ["analytics.orders"],
        "forbidden_columns": ["analytics.orders.customer_email"],
        "max_total_cost": 100,
        "receipt_status": "verified",
        "first_row": {"net_revenue": "2000000.00"},
        "tolerance_percent": 0.01,
    }
    expected.update(expected_updates)
    return ReplayScenario(
        name="net revenue replay",
        intent=QueryIntent(question="Revenue", metric="net_revenue"),
        expected=ReplayExpected.model_validate(expected),
    )


def test_load_scenario_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "scenario.yaml"
    path.write_text(
        """
name: order count
intent:
  question: Count orders
  metric: order_count
expected:
  metric: order_count
""".strip(),
        encoding="utf-8",
    )
    loaded = load_scenario(path)
    assert loaded.name == "order count"
    assert loaded.intent.metric == "order_count"


@pytest.mark.asyncio
async def test_replay_reports_semantic_mismatch(service: Any) -> None:
    report = await run_replay(
        service,
        scenario(metric="wrong_metric", allowed_tables=["analytics.other"]),
    )
    assert not report.passed
    assert "metric mismatch" in " ".join(report.stages[0]["errors"])
    assert "unexpected tables" in " ".join(report.stages[0]["errors"])


@pytest.mark.asyncio
async def test_online_replay_stops_at_cost_failure(service: Any, fake_database: Any) -> None:
    fake_database.total_cost = 50
    report = await run_replay(service, scenario(max_total_cost=10), online=True)
    assert not report.passed
    assert [stage["stage"] for stage in report.stages] == [
        "compile_and_policy",
        "preflight",
    ]
    assert "exceeds scenario maximum" in report.stages[-1]["errors"][0]


@pytest.mark.asyncio
async def test_execute_replay_passes_with_numeric_tolerance(service: Any) -> None:
    report = await run_replay(service, scenario(), online=True, execute=True)
    assert report.passed
    assert report.execution_id
    assert report.stages[-1]["stage"] == "execute_and_verify"


@pytest.mark.asyncio
async def test_execute_replay_reports_query_receipt_mismatches(service: Any) -> None:
    report = await run_replay(
        service,
        scenario(
            receipt_status="failed",
            first_row={"missing": 1, "net_revenue": "999.00"},
            tolerance_percent=0,
        ),
        online=True,
        execute=True,
    )
    assert not report.passed
    errors = " ".join(report.stages[-1]["errors"])
    assert "receipt status" in errors
    assert "missing field" in errors
    assert "first_row.net_revenue" in errors


@pytest.mark.parametrize(
    ("actual", "expected", "tolerance", "matches"),
    [
        ("10", 10, 0, True),
        (101, 100, 1, True),
        (102, 100, 1, False),
        (0, 0, 0, True),
        (1, 0, 100, False),
        ("not-a-number", 1, 100, False),
    ],
)
def test_value_matching(actual: Any, expected: Any, tolerance: float, matches: bool) -> None:
    assert _values_match(actual, expected, tolerance_percent=tolerance) is matches
