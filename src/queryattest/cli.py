from __future__ import annotations

import asyncio
import json
import os
import secrets
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.syntax import Syntax

from queryattest.app import create_service
from queryattest.config import AppSettings, load_policy, load_semantics, resolve_project_path
from queryattest.dbt import import_dbt_manifest
from queryattest.replay import load_scenario, run_replay

app = typer.Typer(
    name="queryattest",
    help="Evidence-backed PostgreSQL execution for AI agents over MCP.",
    no_args_is_help=True,
)
console = Console()


@app.command("serve")
def serve(
    transport: Annotated[str, typer.Option(help="stdio or streamable-http")] = "stdio",
) -> None:
    """Run the MCP server."""
    if transport not in {"stdio", "streamable-http"}:
        raise typer.BadParameter("transport must be stdio or streamable-http")
    os.environ["QUERYATTEST_TRANSPORT"] = transport
    from queryattest.server import main

    main()


@app.command("generate-secret")
def generate_secret() -> None:
    """Generate a ticket/store secret suitable for QUERYATTEST_TICKET_SECRET."""
    console.print(secrets.token_urlsafe(48))


@app.command("validate-config")
def validate_config() -> None:
    """Validate environment, policy, semantic catalog, and encrypted store setup."""
    settings = AppSettings()
    settings.validate_runtime()
    policy = load_policy(resolve_project_path(settings.policy_path))
    semantics = load_semantics(resolve_project_path(settings.semantics_path))
    service = create_service(settings)
    chain_valid, event_count = service.store.verify_audit_chain()
    console.print(
        {
            "policy_version": policy.version,
            "semantic_catalog_version": semantics.version,
            "metrics": sorted(semantics.metrics),
            "data_products": sorted(semantics.data_products),
            "principal": {
                "user_id": settings.user_id,
                "roles": settings.role_list,
                "tenant_scoped": settings.tenant_id is not None,
            },
            "audit_chain_valid": chain_valid,
            "audit_event_count": event_count,
        }
    )


@app.command("doctor")
def doctor() -> None:
    """Check configuration and the PostgreSQL safety boundary."""

    async def _run() -> None:
        service = create_service()
        await service.start()
        try:
            database = service.database
            doctor_method = getattr(database, "doctor", None)
            if not callable(doctor_method):
                raise RuntimeError("configured database gateway has no doctor method")
            result = await doctor_method()
            console.print(result)
            if not result.get("safe_role_defaults", False):
                raise typer.Exit(code=1)
        finally:
            await service.stop()

    asyncio.run(_run())


@app.command("replay")
def replay(
    scenario_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    online: Annotated[bool, typer.Option(help="Run PostgreSQL EXPLAIN preflight")] = False,
    execute: Annotated[
        bool, typer.Option(help="Execute the approved query; implies --online")
    ] = False,
) -> None:
    """Replay a recorded intent as a CI regression test."""

    async def _run() -> None:
        service = create_service()
        scenario = load_scenario(scenario_path)
        should_start = online or execute
        if should_start:
            await service.start()
        try:
            report = await run_replay(
                service, scenario, online=(online or execute), execute=execute
            )
        finally:
            if should_start:
                await service.stop()
        rendered = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)
        console.print(Syntax(rendered, "json", word_wrap=True))
        if not report.passed:
            raise typer.Exit(code=1)

    asyncio.run(_run())


@app.command("import-dbt")
def import_dbt(
    manifest_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    output_path: Annotated[Path, typer.Option("--output", "-o")],
    tenant_column: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Generate a conservative semantic-catalog stub from dbt manifest.json."""
    result = import_dbt_manifest(manifest_path, output_path, tenant_column=tenant_column)
    console.print(
        {
            "output": str(output_path),
            "data_product_count": len(result["catalog"]["data_products"]),
            "warnings": result["warnings"],
        }
    )


@app.command("audit-verify")
def audit_verify() -> None:
    """Verify the local hash-chained audit log."""
    service = create_service()
    valid, count = service.store.verify_audit_chain()
    console.print({"valid": valid, "event_count": count})
    if not valid:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
