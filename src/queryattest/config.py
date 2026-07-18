from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from queryattest.crypto import KeyMaterial

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
QUALIFIED_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class PolicyLimits(ConfigModel):
    max_rows: int = Field(default=500, ge=1, le=100_000)
    max_estimated_rows: int = Field(default=250_000, ge=1)
    max_total_cost: float = Field(default=50_000, gt=0)
    max_bind_parameters: int = Field(default=500, ge=1, le=10_000)
    statement_timeout_ms: int = Field(default=5_000, ge=100, le=300_000)
    ticket_ttl_seconds: int = Field(default=120, ge=10, le=3600)
    plan_ttl_seconds: int = Field(default=300, ge=30, le=86_400)


class SqlSafetyPolicy(ConfigModel):
    deny_select_star: bool = True
    require_schema_qualified_tables: bool = True
    forbidden_schemas: list[str] = Field(
        default_factory=lambda: ["pg_catalog", "information_schema"]
    )
    forbidden_functions: list[str] = Field(
        default_factory=lambda: [
            "pg_sleep",
            "dblink",
            "dblink_connect",
            "dblink_exec",
            "lo_export",
            "lo_import",
            "pg_read_file",
            "pg_read_binary_file",
            "pg_ls_dir",
            "query_to_xml",
            "database_to_xml",
            "set_config",
            "nextval",
            "setval",
            "pg_notify",
            "pg_advisory_lock",
            "pg_advisory_lock_shared",
            "pg_try_advisory_lock",
            "pg_try_advisory_lock_shared",
            "pg_advisory_unlock",
            "pg_advisory_unlock_shared",
            "pg_advisory_unlock_all",
            "pg_cancel_backend",
            "pg_terminate_backend",
            "pg_reload_conf",
            "pg_rotate_logfile",
            "pg_create_restore_point",
            "pg_switch_wal",
            "pg_wal_replay_pause",
            "pg_wal_replay_resume",
            "pg_promote",
        ]
    )


class RoleGrant(ConfigModel):
    allow_metrics: list[str] = Field(default_factory=list)
    allow_tables: list[str] = Field(default_factory=list)
    allow_columns: list[str] = Field(default_factory=list)
    deny_columns: list[str] = Field(default_factory=list)


class PolicyConfig(ConfigModel):
    version: str
    limits: PolicyLimits = Field(default_factory=PolicyLimits)
    sql_safety: SqlSafetyPolicy = Field(default_factory=SqlSafetyPolicy)
    roles: dict[str, RoleGrant]


class FieldDefinition(ConfigModel):
    expression: str
    data_type: Literal["string", "integer", "number", "boolean", "date", "timestamp", "uuid"]
    columns: list[str] = Field(min_length=1)
    groupable: bool = True
    filterable: bool = True
    description: str = ""

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, columns: list[str]) -> list[str]:
        for column in columns:
            if not IDENTIFIER_RE.fullmatch(column):
                raise ValueError(f"invalid column identifier: {column}")
        return columns


class DataProductDefinition(ConfigModel):
    table: str
    alias: str = "src"
    tenant_column: str | None = None
    fields: dict[str, FieldDefinition]
    description: str = ""

    @field_validator("table")
    @classmethod
    def validate_table(cls, value: str) -> str:
        if not QUALIFIED_TABLE_RE.fullmatch(value):
            raise ValueError("table must be schema-qualified using simple SQL identifiers")
        return value

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if not IDENTIFIER_RE.fullmatch(value):
            raise ValueError("alias must be a simple SQL identifier")
        return value

    @field_validator("tenant_column")
    @classmethod
    def validate_tenant_column(cls, value: str | None) -> str | None:
        if value is not None and not IDENTIFIER_RE.fullmatch(value):
            raise ValueError("tenant_column must be a simple SQL identifier")
        return value

    @model_validator(mode="after")
    def validate_field_names(self) -> DataProductDefinition:
        invalid = sorted(name for name in self.fields if not IDENTIFIER_RE.fullmatch(name))
        if invalid:
            raise ValueError(f"invalid semantic field names: {invalid}")
        return self


class ResultCheckDefinition(ConfigModel):
    type: Literal["non_null", "min", "max", "row_count_min", "row_count_max", "unique"]
    field: str | None = None
    value: float | int | None = None

    @model_validator(mode="after")
    def validate_check(self) -> ResultCheckDefinition:
        if self.type in {"non_null", "min", "max", "unique"} and not self.field:
            raise ValueError(f"check {self.type} requires field")
        if self.type in {"min", "max", "row_count_min", "row_count_max"} and self.value is None:
            raise ValueError(f"check {self.type} requires value")
        if self.type in {"row_count_min", "row_count_max"} and (
            not isinstance(self.value, int) or isinstance(self.value, bool) or self.value < 0
        ):
            raise ValueError(f"check {self.type} requires a non-negative integer value")
        return self


class MetricDefinition(ConfigModel):
    version: str
    data_product: str
    expression: str
    output_name: str
    columns: list[str] = Field(min_length=1)
    base_filters: list[str] = Field(default_factory=list)
    base_filter_columns: list[str] = Field(default_factory=list)
    description: str = ""
    unit: str | None = None
    checks: list[ResultCheckDefinition] = Field(default_factory=list)

    @field_validator("output_name")
    @classmethod
    def validate_output_name(cls, value: str) -> str:
        if not IDENTIFIER_RE.fullmatch(value):
            raise ValueError("output_name must be a simple SQL identifier")
        return value

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, columns: list[str]) -> list[str]:
        for column in columns:
            if not IDENTIFIER_RE.fullmatch(column):
                raise ValueError(f"invalid column identifier: {column}")
        return columns


class SemanticConfig(ConfigModel):
    version: str
    data_products: dict[str, DataProductDefinition]
    metrics: dict[str, MetricDefinition]

    @model_validator(mode="after")
    def validate_references(self) -> SemanticConfig:
        invalid_products = sorted(
            name for name in self.data_products if not IDENTIFIER_RE.fullmatch(name)
        )
        if invalid_products:
            raise ValueError(f"invalid data product names: {invalid_products}")
        for metric_name, metric in self.metrics.items():
            if not IDENTIFIER_RE.fullmatch(metric_name):
                raise ValueError(f"invalid metric name: {metric_name}")
            if metric.data_product not in self.data_products:
                raise ValueError(
                    f"metric {metric_name} references missing data product {metric.data_product}"
                )
            product = self.data_products[metric.data_product]
            known_columns = {
                column for field in product.fields.values() for column in field.columns
            }
            if product.tenant_column:
                known_columns.add(product.tenant_column)
            unknown = (set(metric.columns) | set(metric.base_filter_columns)) - known_columns
            if unknown:
                raise ValueError(
                    f"metric {metric_name} uses columns not declared by its data product: {sorted(unknown)}"
                )
            for check in metric.checks:
                if check.field is not None and check.field != metric.output_name:
                    raise ValueError(
                        f"metric {metric_name} check {check.type} references unknown output "
                        f"field {check.field}; expected {metric.output_name}"
                    )
        return self


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QUERYATTEST_", env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql://queryattest_reader:queryattest_reader@localhost:5432/queryattest"
    )
    policy_path: Path = Path("config/policy.yaml")
    semantics_path: Path = Path("config/semantics.yaml")
    state_path: Path = Path(".queryattest/state.db")
    ticket_secret: str = ""
    user_id: str = "local-user"
    roles: str = "finance_analyst"
    tenant_id: str | None = "tenant-a"
    transport: Literal["stdio", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65_535)
    allow_insecure_remote_http: bool = False
    db_pool_min_size: int = Field(default=1, ge=1, le=100)
    db_pool_max_size: int = Field(default=5, ge=1, le=100)
    application_name: str = "queryattest"
    otel_enabled: bool = False

    def validate_runtime(self) -> None:
        try:
            KeyMaterial.from_secret(self.ticket_secret)
        except ValueError as exc:
            raise ValueError(
                "QUERYATTEST_TICKET_SECRET must contain at least 32 UTF-8 bytes; "
                "run `queryattest generate-secret`"
            ) from exc
        if self.db_pool_min_size > self.db_pool_max_size:
            raise ValueError("QUERYATTEST_DB_POOL_MIN_SIZE may not exceed DB_POOL_MAX_SIZE")
        if (
            self.transport == "streamable-http"
            and not _is_loopback_host(self.host)
            and not self.allow_insecure_remote_http
        ):
            raise ValueError(
                "streamable HTTP with the environment principal provider may bind only to "
                "a loopback host; set QUERYATTEST_ALLOW_INSECURE_REMOTE_HTTP=true only for an "
                "explicitly isolated disposable environment"
            )

    @property
    def role_list(self) -> list[str]:
        roles = list(dict.fromkeys(role.strip() for role in self.roles.split(",") if role.strip()))
        if not roles:
            raise ValueError("QUERYATTEST_ROLES must contain at least one role")
        return roles


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be an object: {path}")
    return loaded


def load_policy(path: Path) -> PolicyConfig:
    return PolicyConfig.model_validate(_load_yaml(path))


def load_semantics(path: Path) -> SemanticConfig:
    return SemanticConfig.model_validate(_load_yaml(path))


def resolve_project_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return Path(os.getcwd()) / path
