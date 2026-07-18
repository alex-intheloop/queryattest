from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest

from queryattest.models import ExplainEvidence, QueryIntent
from queryattest.store import EncryptedStateStore, PlanStateError, StoreError


def _prepared(service: Any):
    response = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    return response, service.store.get_plan(response.plan_id)


def _explain() -> ExplainEvidence:
    return ExplainEvidence(
        total_cost=1,
        plan_rows=1,
        node_type="Aggregate",
        relation_names=["analytics.orders"],
        database_user="queryattest_reader",
        database_name="queryattest",
        transaction_read_only=True,
    )


def test_store_rejects_unknown_identifiers(service: Any) -> None:
    with pytest.raises(StoreError, match="unknown plan"):
        service.store.get_plan("missing")
    with pytest.raises(StoreError, match="unknown plan"):
        service.store.approve_plan("missing", explain=_explain(), ticket_jti="ticket")
    with pytest.raises(StoreError, match="unknown plan"):
        service.store.reject_plan("missing")
    with pytest.raises(StoreError, match="unknown plan"):
        service.store.consume_plan("missing", ticket_jti="ticket")
    with pytest.raises(StoreError, match="unknown plan"):
        service.store.complete_plan("missing", succeeded=True)
    with pytest.raises(StoreError, match="unknown execution"):
        service.store.get_execution("missing")
    with pytest.raises(StoreError, match="unknown execution"):
        service.store.complete_execution("missing", error="safe-code")


def test_plan_state_machine_rejects_invalid_transitions(service: Any) -> None:
    response, _ = _prepared(service)
    service.store.approve_plan(response.plan_id, explain=_explain(), ticket_jti="ticket")

    with pytest.raises(PlanStateError, match="must be prepared"):
        service.store.approve_plan(response.plan_id, explain=_explain(), ticket_jti="ticket")
    with pytest.raises(PlanStateError, match="must be prepared"):
        service.store.reject_plan(response.plan_id)
    with pytest.raises(PlanStateError, match="identifier"):
        service.store.consume_plan(response.plan_id, ticket_jti="other-ticket")
    with pytest.raises(PlanStateError, match="not executing"):
        service.store.complete_plan(response.plan_id, succeeded=True)


def test_rejected_plan_cannot_be_approved_or_consumed(service: Any) -> None:
    response, _ = _prepared(service)
    service.store.reject_plan(response.plan_id)
    assert service.store.get_plan(response.plan_id).plan.status == "rejected"

    with pytest.raises(PlanStateError, match="must be prepared"):
        service.store.approve_plan(response.plan_id, explain=_explain(), ticket_jti="ticket")
    with pytest.raises(PlanStateError, match="not executable"):
        service.store.consume_plan(response.plan_id, ticket_jti="ticket")


def test_expired_plan_is_persisted_as_expired_before_rejection(service: Any) -> None:
    response, envelope = _prepared(service)
    approved = service.store.approve_plan(
        response.plan_id,
        explain=_explain(),
        ticket_jti="ticket",
    )
    expired = approved.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    stored = envelope.model_copy(
        update={"plan": expired, "explain": _explain(), "ticket_jti": "ticket"}
    )
    with service.store._connect() as connection:
        service.store._update_plan_row(connection, stored)

    with pytest.raises(PlanStateError, match="expired"):
        service.store.consume_plan(response.plan_id, ticket_jti="ticket")
    assert service.store.get_plan(response.plan_id).plan.status == "expired"


def test_plan_completion_records_both_terminal_states(service: Any) -> None:
    response, _ = _prepared(service)
    service.store.approve_plan(response.plan_id, explain=_explain(), ticket_jti="success-ticket")
    service.store.consume_plan(response.plan_id, ticket_jti="success-ticket")
    service.store.complete_plan(response.plan_id, succeeded=True)
    assert service.store.get_plan(response.plan_id).plan.status == "executed"

    failed_response, _ = _prepared(service)
    service.store.approve_plan(
        failed_response.plan_id,
        explain=_explain(),
        ticket_jti="failed-ticket",
    )
    service.store.consume_plan(failed_response.plan_id, ticket_jti="failed-ticket")
    service.store.complete_plan(failed_response.plan_id, succeeded=False)
    assert service.store.get_plan(failed_response.plan_id).plan.status == "failed"


def test_execution_record_lifecycle(service: Any) -> None:
    response, _ = _prepared(service)
    execution = service.store.create_execution(response.plan_id)
    running = service.store.get_execution(execution.execution_id)
    assert running.status == "running"
    assert running.completed_at is None

    service.store.complete_execution(execution.execution_id, error="database_execution_failed")
    failed = service.store.get_execution(execution.execution_id)
    assert failed.status == "failed"
    assert failed.error == "database_execution_failed"
    assert failed.completed_at is not None


def test_audit_filters_and_previous_hash_tampering(service: Any, settings: Any) -> None:
    response, _ = _prepared(service)
    execution = service.store.create_execution(response.plan_id)
    first = service.store.append_audit_event(
        event_type="one",
        actor_fingerprint="actor",
        details={"safe": True},
        plan_id=response.plan_id,
    )
    second = service.store.append_audit_event(
        event_type="two",
        actor_fingerprint="actor",
        details={"safe": True},
        plan_id=response.plan_id,
        execution_id=execution.execution_id,
    )

    assert [
        event["event_id"] for event in service.store.get_audit_events(plan_id=response.plan_id)
    ][-2:] == [first["event_id"], second["event_id"]]
    assert [
        event["event_id"]
        for event in service.store.get_audit_events(execution_id=execution.execution_id)
    ] == [second["event_id"]]
    assert [
        event["event_id"]
        for event in service.store.get_audit_events(
            plan_id=response.plan_id,
            execution_id=execution.execution_id,
        )
    ] == [second["event_id"]]

    with closing(sqlite3.connect(settings.state_path)) as connection:
        connection.execute(
            "UPDATE audit_events SET previous_hash = ? WHERE event_id = ?",
            ("forged", second["event_id"]),
        )
        connection.commit()
    valid, failing_index = service.store.verify_audit_chain()
    assert not valid
    assert failing_index >= 1


def test_decrypt_rejects_short_payload_and_wrong_database_key(service: Any, settings: Any) -> None:
    response, envelope = _prepared(service)
    with pytest.raises(StoreError, match="too short"):
        service.store._decrypt(response.plan_id, b"short")

    encrypted = service.store._encrypt(response.plan_id, envelope)
    with pytest.raises(StoreError, match="authentication"):
        service.store._decrypt("different-plan-id", encrypted)

    with closing(sqlite3.connect(settings.state_path)) as connection:
        connection.execute(
            "UPDATE plans SET encrypted_payload = ? WHERE id = ?",
            (b"short", response.plan_id),
        )
        connection.commit()
    with pytest.raises(StoreError, match="too short"):
        service.store.get_plan(response.plan_id)


@pytest.mark.parametrize(
    ("value", "parameter_type", "expected"),
    [
        (123, "string", "123"),
        ("42", "integer", 42),
        ("12.50", "number", Decimal("12.50")),
        (True, "boolean", True),
        ("false", "boolean", False),
        ("2026-07-18", "date", date(2026, 7, 18)),
        (datetime(2026, 7, 18, 12, tzinfo=UTC), "date", date(2026, 7, 18)),
        (
            "2026-07-18T12:00:00Z",
            "timestamp",
            datetime(2026, 7, 18, 12, tzinfo=UTC),
        ),
        (
            UUID("12345678-1234-5678-1234-567812345678"),
            "uuid",
            UUID("12345678-1234-5678-1234-567812345678"),
        ),
        (
            "12345678-1234-5678-1234-567812345678",
            "uuid",
            UUID("12345678-1234-5678-1234-567812345678"),
        ),
    ],
)
def test_parameter_restoration_is_typed(value: Any, parameter_type: str, expected: Any) -> None:
    assert EncryptedStateStore._restore_parameter(value, parameter_type) == expected


@pytest.mark.parametrize(
    ("value", "parameter_type", "message"),
    [
        (True, "integer", "boolean"),
        ("NaN", "number", "not finite"),
        ("not-a-boolean", "boolean", "invalid"),
        ("2026-07-18T12:00:00", "timestamp", "UTC offset"),
        ("value", "unsupported", "unsupported"),
    ],
)
def test_parameter_restoration_rejects_ambiguous_or_unsafe_values(
    value: Any, parameter_type: str, message: str
) -> None:
    with pytest.raises(StoreError, match=message):
        EncryptedStateStore._restore_parameter(value, parameter_type)
