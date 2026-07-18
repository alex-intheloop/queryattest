from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any

import pytest

from queryattest.canonical import canonical_json
from queryattest.crypto import KeyMaterial
from queryattest.models import PreparedPlan, Principal, QueryIntent
from queryattest.tickets import TicketError, TicketService

TEST_SECRET = "unit-test-secret-0123456789abcdef-0123456789abcdef"


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_json(segment: str) -> dict[str, Any]:
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    decoded = json.loads(raw)
    assert isinstance(decoded, dict)
    return decoded


def _signed_token(
    token: str,
    *,
    header_update: Callable[[dict[str, Any]], None] | None = None,
    payload_update: Callable[[dict[str, Any]], None] | None = None,
    raw_header: bytes | None = None,
    raw_payload: bytes | None = None,
) -> str:
    header_segment, payload_segment, _ = token.split(".")
    if raw_header is None:
        header = _decode_json(header_segment)
        if header_update is not None:
            header_update(header)
        raw_header = canonical_json(header).encode()
    if raw_payload is None:
        payload = _decode_json(payload_segment)
        if payload_update is not None:
            payload_update(payload)
        raw_payload = canonical_json(payload).encode()

    encoded_header = _encode(raw_header)
    encoded_payload = _encode(raw_payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    key = KeyMaterial.from_secret(TEST_SECRET).ticket_signing_key
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_encode(signature)}"


def _issue(service: Any) -> tuple[str, PreparedPlan, Principal]:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()
    token, _ = service.tickets.issue(
        plan,
        principal,
        ttl_seconds=60,
        max_rows=100,
        max_estimated_rows=1000,
        max_total_cost=50_000,
    )
    return token, plan, principal


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"issuer": " "}, "issuer"),
        ({"audience": " "}, "audience"),
        ({"max_ttl_seconds": 0}, "ttl"),
        ({"clock_skew_seconds": -1}, "clock skew"),
    ],
)
def test_ticket_service_rejects_invalid_configuration(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        TicketService(TEST_SECRET, **kwargs)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ttl_seconds": 0}, "ttl"),
        ({"max_rows": 0}, "row cap"),
        ({"max_estimated_rows": -1}, "estimated-row"),
        ({"max_total_cost": -1}, "cost cap"),
    ],
)
def test_ticket_issue_rejects_invalid_approval_bounds(
    service: Any, overrides: dict[str, Any], message: str
) -> None:
    _, plan, principal = _issue(service)
    arguments: dict[str, Any] = {
        "ttl_seconds": 60,
        "max_rows": 100,
        "max_estimated_rows": 1000,
        "max_total_cost": 50_000,
    }
    arguments.update(overrides)
    with pytest.raises(ValueError, match=message):
        service.tickets.issue(plan, principal, **arguments)


def test_ticket_may_not_be_issued_for_an_unrelated_principal(service: Any) -> None:
    _, plan, principal = _issue(service)
    other = principal.model_copy(update={"user_id": "other-user"})
    with pytest.raises(TicketError, match="different from the plan owner"):
        service.tickets.issue(
            plan,
            other,
            ttl_seconds=60,
            max_rows=100,
            max_estimated_rows=1000,
            max_total_cost=50_000,
        )


@pytest.mark.parametrize("token", ["", "not-a-ticket", "a.b.c.d"])
def test_malformed_ticket_shapes_are_rejected(service: Any, token: str) -> None:
    principal = service.principals.current()
    with pytest.raises(TicketError):
        service.tickets.verify(token, principal=principal)


def test_noncanonical_or_duplicate_ticket_json_is_rejected(service: Any) -> None:
    token, _, principal = _issue(service)
    payload = _decode_json(token.split(".")[1])
    duplicate_payload = (
        "{"
        + f'"jti":{json.dumps(payload["jti"])},'
        + f'"jti":{json.dumps(payload["jti"])},'
        + ",".join(
            f"{json.dumps(key)}:{json.dumps(value, separators=(',', ':'))}"
            for key, value in payload.items()
            if key != "jti"
        )
        + "}"
    ).encode()
    duplicate_token = _signed_token(token, raw_payload=duplicate_payload)
    with pytest.raises(TicketError, match="payload"):
        service.tickets.verify(duplicate_token, principal=principal)

    noncanonical = json.dumps(payload, indent=2).encode()
    noncanonical_token = _signed_token(token, raw_payload=noncanonical)
    with pytest.raises(TicketError, match="payload"):
        service.tickets.verify(noncanonical_token, principal=principal)


def test_ticket_json_segments_must_be_objects(service: Any) -> None:
    token, _, principal = _issue(service)
    list_payload = _signed_token(token, raw_payload=b"[]")
    with pytest.raises(TicketError, match="payload"):
        service.tickets.verify(list_payload, principal=principal)


def test_signature_encoding_and_header_are_validated(service: Any) -> None:
    token, _, principal = _issue(service)
    header, payload, _ = token.split(".")
    with pytest.raises(TicketError, match="signature encoding"):
        service.tickets.verify(f"{header}.{payload}.!", principal=principal)

    unsupported = _signed_token(token, header_update=lambda value: value.update({"v": 99}))
    with pytest.raises(TicketError, match="header"):
        service.tickets.verify(unsupported, principal=principal)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        (lambda value: value.update({"expires_at": value["issued_at"]}), "lifetime"),
        (lambda value: value.update({"issuer": "other"}), "issuer or audience"),
        (lambda value: value.update({"audience": "other"}), "issuer or audience"),
        (
            lambda value: value.update(
                {"issued_at": value["issued_at"] + 600, "expires_at": value["expires_at"] + 600}
            ),
            "future",
        ),
    ],
)
def test_signed_but_invalid_temporal_or_context_claims_are_rejected(
    service: Any, update: Callable[[dict[str, Any]], None], message: str
) -> None:
    token, _, principal = _issue(service)
    invalid = _signed_token(token, payload_update=update)
    with pytest.raises(TicketError, match=message):
        service.tickets.verify(invalid, principal=principal)


def test_ticket_binding_fields_are_all_revalidated(service: Any) -> None:
    token, plan, principal = _issue(service)
    other = principal.model_copy(
        update={"user_id": "other-user", "roles": ["auditor"], "tenant_id": "tenant-b"}
    )

    with pytest.raises(TicketError, match="different principal"):
        service.tickets.verify(token, principal=other)

    fingerprint = service.tickets.principal_fingerprint(other)
    subject_mismatch = _signed_token(
        token,
        payload_update=lambda value: value.update(
            {
                "principal_fingerprint": fingerprint,
                "roles_hash": service.tickets.context_digest(
                    "roles", canonical_json(sorted(other.roles))
                ),
                "tenant_hash": service.tickets.context_digest("tenant", other.tenant_id or ""),
            }
        ),
    )
    with pytest.raises(TicketError, match="subject"):
        service.tickets.verify(subject_mismatch, principal=other)

    role_mismatch = _signed_token(
        token,
        payload_update=lambda value: value.update(
            {
                "principal_fingerprint": fingerprint,
                "subject": service.tickets.context_digest("subject", fingerprint),
                "tenant_hash": service.tickets.context_digest("tenant", other.tenant_id or ""),
            }
        ),
    )
    with pytest.raises(TicketError, match="role binding"):
        service.tickets.verify(role_mismatch, principal=other)

    tenant_mismatch = _signed_token(
        token,
        payload_update=lambda value: value.update(
            {
                "principal_fingerprint": fingerprint,
                "subject": service.tickets.context_digest("subject", fingerprint),
                "roles_hash": service.tickets.context_digest(
                    "roles", canonical_json(sorted(other.roles))
                ),
            }
        ),
    )
    with pytest.raises(TicketError, match="tenant binding"):
        service.tickets.verify(tenant_mismatch, principal=other)

    policy_mismatch = _signed_token(
        token, payload_update=lambda value: value.update({"policy_version": "other"})
    )
    with pytest.raises(TicketError, match="different policy"):
        service.tickets.verify(
            policy_mismatch,
            principal=principal,
            expected_policy_version=plan.policy_version,
        )


def test_ticket_must_match_the_exact_expected_plan(service: Any) -> None:
    token, plan, principal = _issue(service)

    other_prepared = service.prepare_query(QueryIntent(question="Revenue 2", metric="net_revenue"))
    other_plan = service.store.get_plan(other_prepared.plan_id).plan
    with pytest.raises(TicketError, match="different plan"):
        service.tickets.verify(token, principal=principal, expected_plan=other_plan)

    wrong_hash = _signed_token(
        token, payload_update=lambda value: value.update({"statement_hash": "f" * 64})
    )
    with pytest.raises(TicketError, match="statement hash"):
        service.tickets.verify(wrong_hash, principal=principal, expected_plan=plan)

    wrong_policy = _signed_token(
        token, payload_update=lambda value: value.update({"policy_version": "other"})
    )
    with pytest.raises(TicketError, match="plan policy"):
        service.tickets.verify(wrong_policy, principal=principal, expected_plan=plan)
