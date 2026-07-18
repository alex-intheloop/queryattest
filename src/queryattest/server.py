from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from queryattest.app import create_service
from queryattest.config import AppSettings
from queryattest.errors import public_error_info
from queryattest.models import (
    AuditEvidence,
    FilterSpec,
    PreflightResponse,
    PreparedPlanResponse,
    QueryIntent,
    QueryReceipt,
    SortSpec,
)
from queryattest.service import QueryAttestService


class AppContext:
    __slots__ = ("service",)

    def __init__(self, service: QueryAttestService) -> None:
        self.service = service


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[AppContext]:
    service = create_service()
    await service.start()
    try:
        yield AppContext(service=service)
    finally:
        await service.stop()


mcp = FastMCP(
    "QueryAttest",
    instructions=(
        "Use list_metrics and describe_metric first. Build a structured intent, then call "
        "prepare_query, preflight_query, and execute_approved_query in that order. Never "
        "invent or alter SQL or execution tickets."
    ),
    lifespan=lifespan,
    json_response=True,
    host=os.getenv("QUERYATTEST_HOST", "127.0.0.1"),
    port=int(os.getenv("QUERYATTEST_PORT", "8000")),
)


def _service(ctx: Context[Any, AppContext]) -> QueryAttestService:
    return ctx.request_context.lifespan_context.service


@mcp.tool()
def list_metrics(ctx: Context[Any, AppContext]) -> dict[str, Any]:
    """List versioned business metrics visible to the authenticated principal."""
    try:
        service = _service(ctx)
        with service.telemetry.span("queryattest.list_metrics"):
            metrics = service.list_metrics()
            return {"metrics": metrics, "count": len(metrics)}
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


@mcp.tool()
def describe_metric(metric_name: str, ctx: Context[Any, AppContext]) -> dict[str, Any]:
    """Describe one metric, its dimensions, filters, source, and result checks."""
    try:
        service = _service(ctx)
        with service.telemetry.span(
            "queryattest.describe_metric", {"queryattest.metric": metric_name}
        ):
            return service.describe_metric(metric_name)
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


@mcp.tool()
def prepare_query(
    question: str,
    metric: str,
    ctx: Context[Any, AppContext],
    dimensions: list[str] | None = None,
    filters: list[FilterSpec] | None = None,
    order_by: list[SortSpec] | None = None,
    limit: int = 100,
) -> PreparedPlanResponse:
    """Compile structured business intent into an immutable parameterized SELECT plan."""
    try:
        intent = QueryIntent(
            question=question,
            metric=metric,
            dimensions=dimensions or [],
            filters=filters or [],
            order_by=order_by or [],
            limit=limit,
        )
        service = _service(ctx)
        with service.telemetry.span("queryattest.prepare_query", {"queryattest.metric": metric}):
            return service.prepare_query(intent)
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


@mcp.tool()
async def preflight_query(plan_id: str, ctx: Context[Any, AppContext]) -> PreflightResponse:
    """Run AST policy and PostgreSQL EXPLAIN guards, then issue a short-lived signed ticket."""
    try:
        service = _service(ctx)
        with service.telemetry.span(
            "queryattest.preflight_query", {"queryattest.plan_id": plan_id}
        ):
            return await service.preflight_query(plan_id)
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


@mcp.tool()
async def execute_approved_query(ticket: str, ctx: Context[Any, AppContext]) -> QueryReceipt:
    """Execute exactly one approved plan in a read-only transaction and return a Query Receipt."""
    try:
        service = _service(ctx)
        with service.telemetry.span("queryattest.execute_approved_query"):
            return await service.execute_approved_query(ticket)
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


@mcp.tool()
def get_audit_evidence(execution_id: str, ctx: Context[Any, AppContext]) -> AuditEvidence:
    """Return redacted evidence and hash-chained audit events for an execution."""
    try:
        service = _service(ctx)
        with service.telemetry.span(
            "queryattest.get_audit_evidence", {"queryattest.execution_id": execution_id}
        ):
            return service.get_audit_evidence(execution_id)
    except Exception as exc:
        raise ToolError(public_error_info(exc).render()) from exc


def main() -> None:
    settings = AppSettings()
    settings.validate_runtime()
    if settings.transport == "streamable-http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
