from __future__ import annotations

import json
from typing import Any

import pytest

from queryattest.errors import public_error_info
from queryattest.models import FilterSpec, QueryIntent
from queryattest.service import AccessDenied, ServiceError


@pytest.mark.asyncio
async def test_plan_is_bound_to_the_current_principal(service: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    principal = service.principals.current()
    service.principals._principal = principal.model_copy(update={"user_id": "different-user"})

    with pytest.raises(AccessDenied, match="different principal"):
        await service.preflight_query(prepared.plan_id)


def test_rejected_prepare_audit_does_not_store_filter_value(service: Any) -> None:
    marker = "SECRET-invalid-timestamp-value"
    with pytest.raises(AccessDenied):
        service.prepare_query(
            QueryIntent(
                question="Revenue after a date",
                metric="net_revenue",
                filters=[FilterSpec(field="completed_at", op="gte", value=marker)],
            )
        )

    events = service.store.get_audit_events()
    serialized = json.dumps(events)
    assert marker not in serialized
    assert events[-1]["event_type"] == "plan.prepare_rejected"
    assert events[-1]["details"]["decision_codes"] == ["semantic.compile_rejected"]


@pytest.mark.asyncio
async def test_preflight_failure_audit_and_public_error_are_sanitized(service: Any) -> None:
    marker = "SECRET-postgres-error-with-dsn"
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))

    async def fail_preflight(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(marker)

    service.database.preflight = fail_preflight
    with pytest.raises(ServiceError) as captured:
        await service.preflight_query(prepared.plan_id)

    events = service.store.get_audit_events(plan_id=prepared.plan_id)
    serialized = json.dumps(events)
    assert marker not in serialized
    assert marker not in public_error_info(captured.value).render()
    assert events[-1]["details"] == {
        "error_code": "internal_error",
        "error_type": "RuntimeError",
    }


@pytest.mark.asyncio
async def test_execution_failure_audit_and_public_error_are_sanitized(service: Any) -> None:
    marker = "SECRET-runtime-database-error"
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)

    async def fail_execute(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(marker)

    service.database.execute = fail_execute
    with pytest.raises(ServiceError) as captured:
        await service.execute_approved_query(preflight.ticket)

    events = service.store.get_audit_events(plan_id=prepared.plan_id)
    serialized = json.dumps(events)
    assert marker not in serialized
    assert marker not in public_error_info(captured.value).render()
    assert events[-1]["event_type"] == "execution.failed"
    assert events[-1]["details"]["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_execution_rejects_database_name_drift(service: Any, fake_database: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    fake_database.execution_database_name = "unexpected_database"

    with pytest.raises(ServiceError, match="identity changed"):
        await service.execute_approved_query(preflight.ticket)
    assert fake_database.executions == 1


@pytest.mark.asyncio
async def test_execution_rejects_non_read_only_drift(service: Any, fake_database: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    fake_database.read_only = False

    with pytest.raises(ServiceError, match="read-only"):
        await service.execute_approved_query(preflight.ticket)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("execution_total_cost", 12.6, "cost exceeds"),
        ("execution_plan_rows", 11, "row estimate exceeds"),
    ],
)
async def test_execution_rejects_upward_planner_drift_bound_by_ticket(
    service: Any,
    fake_database: Any,
    attribute: str,
    value: float | int,
    message: str,
) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    setattr(fake_database, attribute, value)

    with pytest.raises(ServiceError, match=message):
        await service.execute_approved_query(preflight.ticket)


@pytest.mark.asyncio
async def test_ticket_caps_are_bound_to_the_approved_explain(service: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    plan = service.store.get_plan(prepared.plan_id).plan
    claims = service.tickets.verify(
        preflight.ticket,
        principal=service.principals.current(),
        expected_plan=plan,
        expected_policy_version=service.policy_config.version,
    )

    assert claims.max_total_cost == preflight.explain.total_cost
    assert claims.max_estimated_rows == preflight.explain.plan_rows


@pytest.mark.asyncio
async def test_execution_rejects_gateway_row_cap_violation(
    service: Any, fake_database: Any
) -> None:
    fake_database.rows = [
        {"net_revenue": "1.00"},
        {"net_revenue": "2.00"},
    ]
    fake_database.ignore_row_cap = True
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue", limit=1))
    preflight = await service.preflight_query(prepared.plan_id)

    with pytest.raises(ServiceError, match="more rows"):
        await service.execute_approved_query(preflight.ticket)


@pytest.mark.asyncio
async def test_statement_hash_recomputation_includes_parameter_types(service: Any) -> None:
    prepared = service.prepare_query(
        QueryIntent(
            question="Revenue after a date",
            metric="net_revenue",
            filters=[
                FilterSpec(
                    field="completed_at",
                    op="gte",
                    value="2026-07-01T00:00:00Z",
                )
            ],
        )
    )
    preflight = await service.preflight_query(prepared.plan_id)

    envelope = service.store.get_plan(prepared.plan_id)
    altered_compiled = envelope.plan.compiled.model_copy(
        update={"parameter_types": ["string", "string"]}
    )
    altered_plan = envelope.plan.model_copy(update={"compiled": altered_compiled})
    altered_envelope = envelope.model_copy(update={"plan": altered_plan})
    with service.store._connect() as connection:
        service.store._update_plan_row(connection, altered_envelope)

    with pytest.raises(ServiceError, match="hash failed recomputation"):
        await service.execute_approved_query(preflight.ticket)


@pytest.mark.asyncio
async def test_persisted_evidence_redacts_rows_and_identity(service: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    preflight = await service.preflight_query(prepared.plan_id)
    answer = await service.execute_approved_query(preflight.ticket)

    evidence = service.get_audit_evidence(answer.execution_id)
    authorization = evidence.query_receipt_without_rows["authorization"]
    serialized = json.dumps(evidence.model_dump(mode="json"))

    assert evidence.query_receipt_without_rows["answer"] == []
    assert evidence.query_receipt_without_rows["answer_rows_redacted"] is True
    assert authorization["user_id"] == "[redacted]"
    assert authorization["roles"] == ["[redacted]"]
    assert authorization["tenant_scope"] == "[redacted]"
    assert "tenant-a" not in serialized
    assert "finance_analyst" not in serialized
    assert evidence.chain_scope == "global_local_store"
    assert not evidence.independently_verifiable_from_response
