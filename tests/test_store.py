from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from queryattest.models import ExplainEvidence, FilterSpec, QueryIntent
from queryattest.store import PlanStateError


def test_plan_payload_is_encrypted_at_rest(service, settings) -> None:
    question = "highly-sensitive-question-marker"
    response = service.prepare_query(QueryIntent(question=question, metric="net_revenue"))
    assert service.store.get_plan(response.plan_id).plan.intent.question == question

    database_files = [settings.state_path, Path(str(settings.state_path) + "-wal")]
    raw = b"".join(path.read_bytes() for path in database_files if path.exists())
    assert question.encode() not in raw
    assert b"tenant-a" not in raw


def test_plan_ticket_can_be_consumed_only_once(service) -> None:
    response = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    explain = ExplainEvidence(
        total_cost=1,
        plan_rows=1,
        node_type="Aggregate",
        relation_names=["analytics.orders"],
        database_user="queryattest_reader",
        database_name="queryattest",
        transaction_read_only=True,
    )
    service.store.approve_plan(
        response.plan_id,
        explain=explain,
        ticket_jti="ticket-1",
    )
    service.store.consume_plan(response.plan_id, ticket_jti="ticket-1")
    with pytest.raises(PlanStateError, match="not executable"):
        service.store.consume_plan(response.plan_id, ticket_jti="ticket-1")


def test_encrypted_plan_restores_typed_database_parameters(service) -> None:
    response = service.prepare_query(
        QueryIntent(
            question="Revenue after timestamp",
            metric="net_revenue",
            filters=[
                FilterSpec(
                    field="completed_at",
                    op="gte",
                    value="2026-06-01T00:00:00Z",
                )
            ],
        )
    )
    plan = service.store.get_plan(response.plan_id).plan
    assert isinstance(plan.compiled.parameters[1], datetime)
    assert plan.compiled.parameters[1].tzinfo is not None
