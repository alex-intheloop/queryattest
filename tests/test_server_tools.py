from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import queryattest.server as server
from queryattest.models import FilterSpec


def context_for(service: Any) -> Any:
    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context=server.AppContext(service=service))
    )


@pytest.mark.asyncio
async def test_mcp_tool_wrappers_cover_the_verified_flow(service: Any) -> None:
    ctx = context_for(service)
    metrics = server.list_metrics(ctx)
    assert metrics["count"] == 2
    assert server.describe_metric("net_revenue", ctx)["name"] == "net_revenue"

    prepared = server.prepare_query(
        "Revenue after July 1",
        "net_revenue",
        ctx,
        filters=[
            FilterSpec(
                field="completed_at",
                op="gte",
                value="2026-07-01T00:00:00Z",
            )
        ],
    )
    preflight = await server.preflight_query(prepared.plan_id, ctx)
    answer = await server.execute_approved_query(preflight.ticket, ctx)
    evidence = server.get_audit_evidence(answer.execution_id, ctx)

    assert answer.status == "verified"
    assert evidence.execution_id == answer.execution_id


def test_mcp_tool_error_is_stable_and_sanitized(service: Any) -> None:
    ctx = context_for(service)
    with pytest.raises(ToolError, match="access_denied") as captured:
        server.describe_metric("SECRET-missing-metric", ctx)
    assert "SECRET-missing-metric" not in str(captured.value)


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_service(monkeypatch: Any) -> None:
    class FakeService:
        started = False
        stopped = False

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.stopped = True

    fake = FakeService()
    monkeypatch.setattr(server, "create_service", lambda: fake)

    async with server.lifespan(server.mcp) as app_context:
        assert app_context.service is fake
        assert fake.started
    assert fake.stopped


def test_main_selects_configured_transport(monkeypatch: Any) -> None:
    calls: list[str | None] = []

    class FakeSettings:
        transport = "streamable-http"

        def validate_runtime(self) -> None:
            return None

    monkeypatch.setattr(server, "AppSettings", FakeSettings)
    monkeypatch.setattr(server.mcp, "run", lambda transport=None: calls.append(transport))
    server.main()
    assert calls == ["streamable-http"]
