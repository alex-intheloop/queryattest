from __future__ import annotations

import pytest

from queryattest.models import FilterSpec, QueryIntent
from queryattest.service import AccessDenied, PreflightRejected, ServiceError


@pytest.mark.asyncio
async def test_complete_verified_flow_and_ticket_replay_protection(service, fake_database) -> None:
    await service.start()
    try:
        prepared = service.prepare_query(
            QueryIntent(
                question="Doanh thu thuần tháng 6 là bao nhiêu?",
                metric="net_revenue",
                filters=[
                    FilterSpec(
                        field="completed_at",
                        op="gte",
                        value="2026-06-01T00:00:00Z",
                    )
                ],
                limit=100,
            )
        )
        preflight = await service.preflight_query(prepared.plan_id)
        answer = await service.execute_approved_query(preflight.ticket)

        assert answer.status == "verified"
        assert answer.answer == [{"net_revenue": "2000000.00"}]
        assert answer.semantic.binding.metric == "net_revenue"
        assert not answer.semantic.natural_language_mapping_proven
        assert answer.safety.read_only_transaction
        assert answer.safety.structured_intent_recompiled
        assert answer.safety.statement_hash_recomputed
        assert answer.safety.policy_revalidated_at_execution
        assert answer.safety.database_identity_matches_preflight
        assert answer.provenance.result_digest
        assert fake_database.executions == 1

        evidence = service.get_audit_evidence(answer.execution_id)
        assert evidence.chain_valid
        assert evidence.query_receipt_without_rows["answer"] == []
        assert [event["event_type"] for event in evidence.event_chain] == [
            "plan.prepared",
            "plan.approved",
            "execution.started",
            "execution.completed",
        ]

        with pytest.raises(AccessDenied, match="not executable"):
            await service.execute_approved_query(preflight.ticket)
        assert fake_database.executions == 1
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_preflight_rejects_excessive_cost(service, fake_database) -> None:
    fake_database.total_cost = 999999
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    with pytest.raises(PreflightRejected, match="exceeds"):
        await service.preflight_query(prepared.plan_id)


@pytest.mark.asyncio
async def test_execution_rejects_cost_drift_after_preflight(service, fake_database) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    fake_database.execution_total_cost = 999999

    with pytest.raises(ServiceError, match="cost exceeds"):
        await service.execute_approved_query(preflight.ticket)

    events = service.store.get_audit_events(plan_id=prepared.plan_id)
    assert events[-1]["event_type"] == "execution.failed"


@pytest.mark.asyncio
async def test_execution_rejects_relation_drift_after_preflight(service, fake_database) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    fake_database.execution_relations = ["analytics.unreviewed_table"]

    with pytest.raises(ServiceError, match="relations differ"):
        await service.execute_approved_query(preflight.ticket)
