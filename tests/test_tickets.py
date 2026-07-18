from __future__ import annotations

import base64

import pytest

from queryattest.models import QueryIntent
from queryattest.tickets import TicketError, TicketService

TEST_SECRET = "unit-test-secret-0123456789abcdef-0123456789abcdef"


def test_ticket_is_bound_to_plan_and_principal(service) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()
    ticket, claims = service.tickets.issue(
        plan,
        principal,
        ttl_seconds=60,
        max_rows=100,
        max_estimated_rows=1000,
        max_total_cost=50000,
    )
    verified = service.tickets.verify(
        ticket,
        principal=principal,
        expected_plan=plan,
        expected_policy_version=plan.policy_version,
    )
    assert verified.jti == claims.jti
    assert verified.statement_hash == plan.compiled.statement_hash


def test_ticket_tampering_is_rejected(service) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()
    ticket, _ = service.tickets.issue(
        plan,
        principal,
        ttl_seconds=60,
        max_rows=100,
        max_estimated_rows=1000,
        max_total_cost=50000,
    )
    replacement = "A" if ticket[-1] != "A" else "B"
    tampered = ticket[:-1] + replacement
    with pytest.raises(TicketError, match="signature"):
        service.tickets.verify(tampered, principal=principal)


def test_expired_ticket_is_rejected(service) -> None:
    now = [1000.0]
    tickets = TicketService(TEST_SECRET, clock=lambda: now[0])
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()
    ticket, _ = tickets.issue(
        plan,
        principal,
        ttl_seconds=10,
        max_rows=100,
        max_estimated_rows=1000,
        max_total_cost=50000,
    )
    now[0] = 1011.0
    with pytest.raises(TicketError, match="expired"):
        tickets.verify(ticket, principal=principal)


def test_ticket_payload_does_not_expose_raw_identity_context(service) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()
    ticket, claims = service.tickets.issue(
        plan,
        principal,
        ttl_seconds=60,
        max_rows=100,
        max_estimated_rows=1000,
        max_total_cost=50000,
    )
    encoded_payload = ticket.split(".")[1]
    encoded_payload += "=" * (-len(encoded_payload) % 4)
    decoded_payload = base64.urlsafe_b64decode(encoded_payload).decode()

    assert principal.user_id not in decoded_payload
    assert principal.tenant_id not in decoded_payload
    assert all(role not in decoded_payload for role in principal.roles)
    assert claims.subject != principal.user_id
