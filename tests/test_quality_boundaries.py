from __future__ import annotations

import base64
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier
from typing import Any

import pytest
from pydantic import ValidationError

from queryattest.canonical import canonical_json
from queryattest.config import AppSettings, SemanticConfig
from queryattest.crypto import KeyMaterial, KeyMaterialError
from queryattest.errors import public_error_info, safe_error_details
from queryattest.models import ExplainEvidence, Principal, QueryIntent
from queryattest.service import ServiceError
from queryattest.store import PlanStateError, StoreError
from queryattest.tickets import TicketError, TicketService
from queryattest.verifier import ResultVerifier

TEST_SECRET = "quality-secret-0123456789abcdef-0123456789abcdef"
OTHER_SECRET = "quality-secret-fedcba9876543210-fedcba9876543210"


def test_key_material_requires_minimum_byte_length() -> None:
    with pytest.raises(KeyMaterialError, match="at least 32 bytes"):
        KeyMaterial.from_secret("too-short")


def test_key_derivation_is_stable_and_domain_separated() -> None:
    first = KeyMaterial.from_secret(TEST_SECRET)
    second = KeyMaterial.from_secret(TEST_SECRET)
    other = KeyMaterial.from_secret(OTHER_SECRET)

    assert first == second
    assert len({first.ticket_signing_key, first.context_hmac_key, first.state_encryption_key}) == 3
    assert first.key_id != other.key_id
    assert first.context_digest("tenant", "tenant-a") != first.context_digest(
        "principal", "tenant-a"
    )


def test_remote_http_is_denied_by_default() -> None:
    settings = AppSettings(
        ticket_secret=TEST_SECRET,
        transport="streamable-http",
        host="0.0.0.0",
    )
    with pytest.raises(ValueError, match="loopback"):
        settings.validate_runtime()


def test_remote_http_requires_explicit_unsafe_override() -> None:
    settings = AppSettings(
        ticket_secret=TEST_SECRET,
        transport="streamable-http",
        host="0.0.0.0",
        allow_insecure_remote_http=True,
    )
    settings.validate_runtime()


def test_pool_bounds_and_roles_are_validated() -> None:
    with pytest.raises(ValueError, match="may not exceed"):
        AppSettings(
            ticket_secret=TEST_SECRET,
            db_pool_min_size=4,
            db_pool_max_size=2,
        ).validate_runtime()

    settings = AppSettings(ticket_secret=TEST_SECRET, roles="analyst, analyst, auditor")
    assert settings.role_list == ["analyst", "auditor"]


def test_identity_values_are_normalized_and_blank_values_rejected() -> None:
    principal = Principal(
        user_id="  alex  ",
        roles=[" analyst ", "analyst"],
        tenant_id=" tenant-a ",
        source=" environment ",
    )
    assert principal.user_id == "alex"
    assert principal.roles == ["analyst"]
    assert principal.tenant_id == "tenant-a"
    assert principal.source == "environment"

    with pytest.raises(ValidationError, match="blank"):
        Principal(user_id="   ", roles=["analyst"], tenant_id="tenant-a")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_floats(value: float) -> None:
    with pytest.raises(ValueError):
        canonical_json(value)


def test_semantic_dictionary_keys_are_sql_identifiers(service: Any) -> None:
    raw = service.catalog.config.model_dump(mode="python")
    product = raw["data_products"].pop("orders")
    raw["data_products"]["orders;drop"] = product

    with pytest.raises(ValidationError, match="invalid data product names"):
        SemanticConfig.model_validate(raw)


def test_result_checks_may_only_reference_metric_output(service: Any) -> None:
    raw = service.catalog.config.model_dump(mode="python")
    raw["metrics"]["net_revenue"]["checks"][0]["field"] = "customer_email"

    with pytest.raises(ValidationError, match="unknown output field"):
        SemanticConfig.model_validate(raw)


def test_ticket_v2_contains_key_id_and_rejects_other_key(service: Any) -> None:
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

    encoded_header = token.split(".", maxsplit=1)[0]
    encoded_header += "=" * (-len(encoded_header) % 4)
    header = json.loads(base64.urlsafe_b64decode(encoded_header))
    assert header == {
        "alg": "HS256",
        "kid": service.tickets.key_id,
        "typ": "QAT",
        "v": 2,
    }

    other = TicketService(OTHER_SECRET)
    with pytest.raises(TicketError, match="signature"):
        other.verify(token, principal=principal)


def test_ticket_limits_are_checked_before_issue_and_parse(service: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    plan = service.store.get_plan(prepared.plan_id).plan
    principal = service.principals.current()

    with pytest.raises(ValueError, match="ttl"):
        service.tickets.issue(
            plan,
            principal,
            ttl_seconds=service.tickets.max_ttl_seconds + 1,
            max_rows=100,
            max_estimated_rows=1000,
            max_total_cost=50_000,
        )
    with pytest.raises(TicketError, match="length"):
        service.tickets.verify("x" * (TicketService.MAX_TOKEN_LENGTH + 1), principal=principal)


def test_public_error_boundary_never_echoes_internal_message() -> None:
    secret_marker = "postgres://admin:password@internal/tenant-a"
    exc = ServiceError(secret_marker)

    rendered = public_error_info(exc).render()
    details = safe_error_details(exc)
    assert secret_marker not in rendered
    assert secret_marker not in json.dumps(details)
    assert details == {
        "error_code": "service_operation_failed",
        "error_type": "ServiceError",
    }


def test_state_file_permissions_are_owner_only(settings: AppSettings, service: Any) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission bits are unavailable")
    service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    assert settings.state_path.stat().st_mode & 0o777 == 0o600


def test_tampered_encrypted_plan_is_rejected(service: Any, settings: AppSettings) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    with closing(sqlite3.connect(settings.state_path)) as connection:
        row = connection.execute(
            "SELECT encrypted_payload FROM plans WHERE id = ?", (prepared.plan_id,)
        ).fetchone()
        assert row is not None
        payload = bytearray(row[0])
        payload[-1] ^= 1
        connection.execute(
            "UPDATE plans SET encrypted_payload = ? WHERE id = ?",
            (bytes(payload), prepared.plan_id),
        )
        connection.commit()

    with pytest.raises(StoreError, match="authentication"):
        service.store.get_plan(prepared.plan_id)


def test_plan_consumption_is_atomic_under_concurrency(service: Any) -> None:
    prepared = service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    explain = ExplainEvidence(
        total_cost=1,
        plan_rows=1,
        node_type="Aggregate",
        relation_names=["analytics.orders"],
        database_user="queryattest_reader",
        database_name="queryattest",
        transaction_read_only=True,
    )
    service.store.approve_plan(prepared.plan_id, explain=explain, ticket_jti="one-shot")
    barrier = Barrier(2)

    def consume() -> str:
        barrier.wait(timeout=5)
        try:
            service.store.consume_plan(prepared.plan_id, ticket_jti="one-shot")
            return "consumed"
        except PlanStateError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: consume(), range(2)))

    assert sorted(outcomes) == ["consumed", "rejected"]


def test_audit_chain_tampering_is_detected(service: Any, settings: AppSettings) -> None:
    service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))
    valid, count = service.store.verify_audit_chain()
    assert valid and count == 1

    with closing(sqlite3.connect(settings.state_path)) as connection:
        connection.execute(
            "UPDATE audit_events SET details_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
        connection.commit()

    valid, failing_index = service.store.verify_audit_chain()
    assert not valid
    assert failing_index == 0


def test_verification_failure_does_not_persist_raw_values(service: Any) -> None:
    metric = service.catalog.metric_definition("net_revenue")
    sensitive_value = "SECRET-CUSTOMER-VALUE"
    status, checks, _ = ResultVerifier().verify(
        [{"net_revenue": sensitive_value}], metric, truncated=False
    )

    serialized = json.dumps([check.model_dump(mode="json") for check in checks])
    assert status == "failed"
    assert sensitive_value not in serialized
    assert "non_numeric_value" in serialized
