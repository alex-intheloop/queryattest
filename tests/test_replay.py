from __future__ import annotations

import pytest

from queryattest.models import QueryIntent
from queryattest.replay import ReplayExpected, ReplayScenario, run_replay


@pytest.mark.asyncio
async def test_offline_replay_checks_provenance(service) -> None:
    scenario = ReplayScenario(
        name="net revenue receipt",
        intent=QueryIntent(question="Revenue", metric="net_revenue"),
        expected=ReplayExpected(
            metric="net_revenue",
            allowed_tables=["analytics.orders"],
            forbidden_columns=["analytics.orders.customer_email"],
        ),
    )
    report = await run_replay(service, scenario)
    assert report.passed
    assert report.stages[0]["stage"] == "compile_and_policy"
