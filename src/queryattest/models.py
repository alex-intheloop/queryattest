from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

JsonScalar = str | int | float | bool | None


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False, allow_inf_nan=False)


class FilterOperator(StrEnum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    BETWEEN = "between"
    IS_NULL = "is_null"
    NOT_NULL = "not_null"


class FilterSpec(StrictModel):
    field: str = Field(min_length=1, max_length=128)
    op: FilterOperator = FilterOperator.EQ
    value: JsonScalar | list[JsonScalar] = None

    @field_validator("value")
    @classmethod
    def validate_value_for_operator(
        cls, value: JsonScalar | list[JsonScalar], info: Any
    ) -> JsonScalar | list[JsonScalar]:
        op = info.data.get("op")
        if op in {FilterOperator.IS_NULL, FilterOperator.NOT_NULL}:
            return None
        if isinstance(value, list) and len(value) > 100:
            raise ValueError("filter lists may contain at most 100 values")
        scalar_values = value if isinstance(value, list) else [value]
        if any(isinstance(item, str) and len(item) > 4096 for item in scalar_values):
            raise ValueError("filter string values may contain at most 4096 characters")
        if op in {FilterOperator.IN, FilterOperator.NOT_IN, FilterOperator.BETWEEN}:
            if not isinstance(value, list):
                raise ValueError(f"operator {op} requires a list value")
            if op == FilterOperator.BETWEEN and len(value) != 2:
                raise ValueError("between requires exactly two values")
            if op in {FilterOperator.IN, FilterOperator.NOT_IN} and not value:
                raise ValueError(f"operator {op} requires at least one value")
        elif isinstance(value, list):
            raise ValueError(f"operator {op} requires a scalar value")
        return value


class SortDirection(StrEnum):
    ASC = "asc"
    DESC = "desc"


class SortSpec(StrictModel):
    field: str = Field(min_length=1, max_length=128)
    direction: SortDirection = SortDirection.ASC


class QueryIntent(StrictModel):
    question: str = Field(min_length=1, max_length=4000)
    metric: str = Field(min_length=1, max_length=128)
    dimensions: list[str] = Field(default_factory=list, max_length=20)
    filters: list[FilterSpec] = Field(default_factory=list, max_length=50)
    order_by: list[SortSpec] = Field(default_factory=list, max_length=10)
    limit: int = Field(default=100, ge=1, le=10_000)


class Principal(StrictModel):
    user_id: str = Field(min_length=1, max_length=256)
    roles: list[str] = Field(min_length=1, max_length=50)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=256)
    source: str = Field(default="environment", min_length=1, max_length=128)

    @field_validator("user_id", "tenant_id", "source")
    @classmethod
    def normalize_identity_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("identity values may not be blank")
        return normalized

    @field_validator("roles")
    @classmethod
    def normalize_roles(cls, roles: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_role in roles:
            role = raw_role.strip()
            if not role:
                raise ValueError("principal roles may not be blank")
            if len(role) > 128:
                raise ValueError("principal role names may contain at most 128 characters")
            if role not in seen:
                normalized.append(role)
                seen.add(role)
        return normalized


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    INFO = "info"


class PolicyDecision(StrictModel):
    code: str
    outcome: PolicyOutcome
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class SemanticBinding(StrictModel):
    metric: str
    metric_version: str
    data_product: str
    dimensions: list[str]
    filters: list[str]
    source_tables: list[str]
    source_columns: list[str]
    output_fields: list[str]
    semantic_catalog_version: str


class CompiledQuery(StrictModel):
    sql: str
    parameters: list[Any]
    parameter_types: list[str]
    statement_hash: str
    semantic_binding: SemanticBinding


class PreparedPlan(StrictModel):
    plan_id: str
    created_at: datetime
    expires_at: datetime
    status: Literal[
        "prepared", "approved", "executing", "executed", "failed", "rejected", "expired"
    ]
    intent: QueryIntent
    principal: Principal
    principal_fingerprint: str
    compiled: CompiledQuery
    policy_version: str
    policy_decisions: list[PolicyDecision]


class PreparedPlanResponse(StrictModel):
    plan_id: str
    status: str
    expires_at: datetime
    sql_template: str
    parameter_count: int
    semantic_binding: SemanticBinding
    policy_decisions: list[PolicyDecision]
    next_step: str = "Call preflight_query with this plan_id."


class ExplainEvidence(StrictModel):
    total_cost: float
    plan_rows: int
    plan_width: int | None = None
    node_type: str
    relation_names: list[str] = Field(default_factory=list)
    database_user: str
    database_name: str
    transaction_read_only: bool


class TicketClaims(StrictModel):
    jti: str = Field(min_length=1, max_length=128)
    issuer: str = Field(min_length=1, max_length=128)
    audience: str = Field(min_length=1, max_length=128)
    subject: str = Field(min_length=32, max_length=128)
    plan_id: str = Field(min_length=1, max_length=128)
    statement_hash: str = Field(min_length=32, max_length=128)
    principal_fingerprint: str = Field(min_length=32, max_length=128)
    tenant_hash: str | None = Field(default=None, min_length=32, max_length=128)
    roles_hash: str = Field(min_length=32, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    max_rows: int = Field(ge=1, le=100_000)
    max_estimated_rows: int = Field(ge=0)
    max_total_cost: float = Field(ge=0)


class PreflightResponse(StrictModel):
    plan_id: str
    status: Literal["approved"]
    ticket: str
    ticket_expires_at: datetime
    explain: ExplainEvidence
    policy_decisions: list[PolicyDecision]
    next_step: str = "Call execute_approved_query with this exact ticket."


class VerificationCheck(StrictModel):
    name: str
    passed: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ProvenanceEvidence(StrictModel):
    plan_id: str
    execution_id: str
    query_hash: str
    metric: str
    metric_version: str
    semantic_catalog_version: str
    source_tables: list[str]
    source_columns: list[str]
    snapshot_time: datetime
    result_digest: str


class AuthorizationEvidence(StrictModel):
    user_id: str
    roles: list[str]
    tenant_scope: str | None
    principal_fingerprint: str
    policy_version: str
    decisions: list[PolicyDecision]


class SafetyEvidence(StrictModel):
    ast_validated: bool
    single_statement: bool
    structured_intent_recompiled: bool
    statement_hash_recomputed: bool
    policy_revalidated_at_execution: bool
    read_only_transaction: bool
    database_user: str
    database_name: str
    database_identity_basis: list[str] = Field(
        default_factory=lambda: ["database_user", "database_name"]
    )
    database_identity_matches_preflight: bool
    preflight_explain_total_cost: float
    preflight_explain_plan_rows: int
    explain_total_cost: float
    explain_plan_rows: int
    relations_rechecked_in_execution_transaction: bool
    statement_timeout_ms: int
    max_rows: int
    truncated: bool


class SemanticEvidence(StrictModel):
    binding: SemanticBinding
    compiled_from_structured_intent: bool = True
    natural_language_mapping_proven: bool = False
    note: str = (
        "The receipt attests that executed SQL matches the declared structured intent. "
        "It does not mathematically prove that the agent mapped the original natural-language "
        "question to the correct metric."
    )


class QueryReceipt(StrictModel):
    receipt_version: str = "1.1"
    status: Literal["verified", "partially_verified", "failed"]
    execution_id: str
    answer: list[dict[str, Any]]
    row_count: int
    semantic: SemanticEvidence
    authorization: AuthorizationEvidence
    safety: SafetyEvidence
    verification: list[VerificationCheck]
    provenance: ProvenanceEvidence
    warnings: list[str] = Field(default_factory=list)


class AuditEvidence(StrictModel):
    execution_id: str
    plan_id: str
    event_chain: list[dict[str, Any]]
    chain_valid: bool
    global_chain_event_count: int
    chain_scope: Literal["global_local_store"] = "global_local_store"
    independently_verifiable_from_response: bool = False
    query_receipt_without_rows: dict[str, Any]
