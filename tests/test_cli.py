from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import queryattest.cli as cli

ROOT = Path(__file__).resolve().parents[1]
TEST_SECRET = "cli-test-secret-0123456789abcdef-0123456789abcdef"
runner = CliRunner()


def configure_environment(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("QUERYATTEST_TICKET_SECRET", TEST_SECRET)
    monkeypatch.setenv("QUERYATTEST_POLICY_PATH", str(ROOT / "config" / "policy.yaml"))
    monkeypatch.setenv("QUERYATTEST_SEMANTICS_PATH", str(ROOT / "config" / "semantics.yaml"))
    monkeypatch.setenv("QUERYATTEST_STATE_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("QUERYATTEST_USER_ID", "cli-user")
    monkeypatch.setenv("QUERYATTEST_ROLES", "finance_analyst")
    monkeypatch.setenv("QUERYATTEST_TENANT_ID", "tenant-a")


def test_generate_secret_outputs_strong_random_material() -> None:
    result = runner.invoke(cli.app, ["generate-secret"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) >= 64


def test_validate_config_and_audit_verify(monkeypatch: Any, tmp_path: Path) -> None:
    configure_environment(monkeypatch, tmp_path)

    validate = runner.invoke(cli.app, ["validate-config"])
    assert validate.exit_code == 0
    assert "2026-07-16.1" in validate.stdout
    assert "net_revenue" in validate.stdout

    audit = runner.invoke(cli.app, ["audit-verify"])
    assert audit.exit_code == 0
    assert "True" in audit.stdout


def test_offline_replay_command(monkeypatch: Any, tmp_path: Path) -> None:
    configure_environment(monkeypatch, tmp_path)
    result = runner.invoke(
        cli.app,
        ["replay", str(ROOT / "tests" / "scenarios" / "net_revenue.yaml")],
    )
    assert result.exit_code == 0
    assert '"passed": true' in result.stdout


def test_import_dbt_command(tmp_path: Path) -> None:
    manifest = {
        "metadata": {"dbt_version": "1.10.0"},
        "nodes": {
            "model.demo.orders": {
                "resource_type": "model",
                "name": "orders",
                "schema": "analytics",
                "alias": "orders",
                "columns": {
                    "order_id": {"data_type": "bigint", "description": "ID"},
                },
            }
        },
    }
    manifest_path = tmp_path / "manifest.json"
    output_path = tmp_path / "semantics.yaml"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = runner.invoke(
        cli.app,
        ["import-dbt", str(manifest_path), "--output", str(output_path)],
    )
    assert result.exit_code == 0
    assert output_path.exists()
    assert "orders" in output_path.read_text(encoding="utf-8")


def test_serve_rejects_unknown_transport() -> None:
    result = runner.invoke(cli.app, ["serve", "--transport", "websocket"])
    assert result.exit_code != 0
    assert "transport must be" in result.output


def test_doctor_uses_gateway_health_report(monkeypatch: Any) -> None:
    class FakeDatabase:
        async def doctor(self) -> dict[str, Any]:
            return {"safe_role_defaults": True, "warnings": []}

    class FakeService:
        database = FakeDatabase()
        started = False

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.started = False

    fake = FakeService()
    monkeypatch.setattr(cli, "create_service", lambda: fake)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "safe_role_defaults" in result.stdout
    assert not fake.started
