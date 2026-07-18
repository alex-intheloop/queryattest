from __future__ import annotations

import os
from pathlib import Path

import asyncpg
import pytest

from queryattest.app import create_service
from queryattest.config import AppSettings
from queryattest.models import QueryIntent
from queryattest.service import AccessDenied

ROOT = Path(__file__).resolve().parents[2]
TEST_SECRET = "integration-secret-0123456789abcdef-0123456789abcdef"


def settings_for(tmp_path: Path, database_url: str, *, tenant_id: str | None) -> AppSettings:
    suffix = tenant_id or "unscoped"
    return AppSettings(
        database_url=database_url,
        policy_path=ROOT / "config" / "policy.yaml",
        semantics_path=ROOT / "config" / "semantics.yaml",
        state_path=tmp_path / f"state-{suffix}.db",
        ticket_secret=TEST_SECRET,
        user_id=f"integration-{suffix}",
        roles="finance_analyst",
        tenant_id=tenant_id,
    )


@pytest.fixture
def database_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value:
        pytest.skip("TEST_DATABASE_URL is not configured")
    return value


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tenant_id", "expected"),
    [
        ("tenant-a", [{"net_revenue": "2000000.00"}]),
        ("tenant-b", [{"net_revenue": "9900000.00"}]),
    ],
)
async def test_real_postgres_enforces_tenant_rls(
    tmp_path: Path,
    database_url: str,
    tenant_id: str,
    expected: list[dict[str, str]],
) -> None:
    service = create_service(settings_for(tmp_path, database_url, tenant_id=tenant_id))
    await service.start()
    try:
        prepared = service.prepare_query(
            QueryIntent(question="Revenue", metric="net_revenue", limit=10)
        )
        preflight = await service.preflight_query(prepared.plan_id)
        answer = await service.execute_approved_query(preflight.ticket)
        assert answer.answer == expected
        assert answer.authorization.tenant_scope == tenant_id
        assert answer.safety.read_only_transaction
        assert answer.safety.database_name == "queryattest"
        assert preflight.explain.relation_names == ["analytics.orders"]
    finally:
        await service.stop()


@pytest.mark.integration
def test_unscoped_principal_is_rejected_before_database_execution(
    tmp_path: Path, database_url: str
) -> None:
    service = create_service(settings_for(tmp_path, database_url, tenant_id=None))
    with pytest.raises(AccessDenied, match="tenant-scoped"):
        service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reader_role_has_safe_defaults_and_cannot_write(
    tmp_path: Path, database_url: str
) -> None:
    service = create_service(settings_for(tmp_path, database_url, tenant_id="tenant-a"))
    await service.start()
    try:
        doctor = await service.database.doctor()  # type: ignore[attr-defined]
        assert doctor["safe_role_defaults"] is True
        assert doctor["role_flags"] == {
            "superuser": False,
            "create_role": False,
            "create_database": False,
            "replication": False,
            "bypass_rls": False,
        }
    finally:
        await service.stop()

    connection = await asyncpg.connect(database_url)
    try:
        with pytest.raises(asyncpg.PostgresError):
            await connection.execute(
                "INSERT INTO analytics.orders "
                "(tenant_id, net_amount, completed_at, status, channel, country, customer_email) "
                "VALUES ('tenant-a', 1, now(), 'completed', 'test', 'VN', 'blocked@example.test')"
            )
    finally:
        await connection.close()
