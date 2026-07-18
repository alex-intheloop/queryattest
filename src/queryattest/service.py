from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from queryattest.canonical import sha256_json
from queryattest.config import AppSettings, PolicyConfig
from queryattest.database import DatabaseGateway
from queryattest.errors import public_error_info, safe_error_details
from queryattest.identity import PrincipalProvider
from queryattest.models import (
    AuditEvidence,
    AuthorizationEvidence,
    ExplainEvidence,
    PolicyDecision,
    PolicyOutcome,
    PreflightResponse,
    PreparedPlan,
    PreparedPlanResponse,
    ProvenanceEvidence,
    QueryIntent,
    QueryReceipt,
    SafetyEvidence,
    SemanticEvidence,
    VerificationCheck,
)
from queryattest.policy import PolicyEngine, PolicyViolation
from queryattest.semantics import SemanticCatalog
from queryattest.store import (
    EncryptedStateStore,
    PlanStateError,
    StoredPlanEnvelope,
    StoreError,
    redacted_query_receipt,
)
from queryattest.telemetry import Telemetry
from queryattest.tickets import TicketError, TicketService
from queryattest.verifier import ResultVerifier

logger = logging.getLogger(__name__)


class ServiceError(RuntimeError):
    public_code = "service_operation_failed"
    public_message = "The requested operation could not be completed safely."


class AccessDenied(ServiceError):
    public_code = "access_denied"
    public_message = "The request is not authorized or its execution capability is no longer valid."


class PreflightRejected(ServiceError):
    public_code = "preflight_rejected"
    public_message = "The query plan was rejected by one or more safety checks."

    def __init__(self, message: str, decisions: list[PolicyDecision]) -> None:
        super().__init__(message)
        self.decisions = decisions


class QueryAttestService:
    def __init__(
        self,
        *,
        settings: AppSettings,
        policy_config: PolicyConfig,
        catalog: SemanticCatalog,
        policy: PolicyEngine,
        tickets: TicketService,
        store: EncryptedStateStore,
        database: DatabaseGateway,
        principals: PrincipalProvider,
        verifier: ResultVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.policy_config = policy_config
        self.catalog = catalog
        self.policy = policy
        self.tickets = tickets
        self.store = store
        self.database = database
        self.principals = principals
        self.verifier = verifier or ResultVerifier()
        self.telemetry = Telemetry(settings.otel_enabled)

    async def start(self) -> None:
        await self.database.start()

    async def stop(self) -> None:
        await self.database.stop()

    def list_metrics(self) -> list[dict[str, Any]]:
        principal = self.principals.current()
        return [
            metric
            for metric in self.catalog.list_metrics()
            if self._metric_visible(principal.roles, metric["name"])
        ]

    def describe_metric(self, metric_name: str) -> dict[str, Any]:
        principal = self.principals.current()
        if not self._metric_visible(principal.roles, metric_name):
            raise AccessDenied(f"metric is not visible to this principal: {metric_name}")
        return self.catalog.describe_metric(metric_name)

    def prepare_query(self, intent: QueryIntent) -> PreparedPlanResponse:
        principal = self.principals.current()
        fingerprint = self.tickets.principal_fingerprint(principal)
        try:
            compiled = self.catalog.compile(
                intent,
                principal,
                max_rows=self.policy_config.limits.max_rows,
                max_parameters=self.policy_config.limits.max_bind_parameters,
            )
            decisions = self.policy.enforce(principal, compiled)
        except (ValueError, PolicyViolation) as exc:
            if isinstance(exc, PolicyViolation):
                decisions = exc.decisions
            else:
                decisions = [
                    PolicyDecision(
                        code="semantic.compile_rejected",
                        outcome=PolicyOutcome.DENY,
                        message=str(exc),
                    )
                ]
            self.store.append_audit_event(
                event_type="plan.prepare_rejected",
                actor_fingerprint=fingerprint,
                details={
                    "metric": intent.metric,
                    "question_hash": self.tickets.context_digest("question", intent.question),
                    "decision_codes": [decision.code for decision in decisions],
                    "reason_type": type(exc).__name__,
                },
            )
            raise AccessDenied(str(exc)) from exc

        now = datetime.now(UTC)
        plan = PreparedPlan(
            plan_id=str(uuid4()),
            created_at=now,
            expires_at=now + timedelta(seconds=self.policy_config.limits.plan_ttl_seconds),
            status="prepared",
            intent=intent,
            principal=principal,
            principal_fingerprint=fingerprint,
            compiled=compiled,
            policy_version=self.policy_config.version,
            policy_decisions=decisions,
        )
        self.store.put_plan(plan)
        self.store.append_audit_event(
            event_type="plan.prepared",
            actor_fingerprint=fingerprint,
            plan_id=plan.plan_id,
            details={
                "metric": intent.metric,
                "question_hash": self.tickets.context_digest("question", intent.question),
                "statement_hash": compiled.statement_hash,
                "semantic_binding": compiled.semantic_binding.model_dump(mode="json"),
                "policy_decision_codes": [decision.code for decision in decisions],
            },
        )
        return PreparedPlanResponse(
            plan_id=plan.plan_id,
            status=plan.status,
            expires_at=plan.expires_at,
            sql_template=compiled.sql,
            parameter_count=len(compiled.parameters),
            semantic_binding=compiled.semantic_binding,
            policy_decisions=decisions,
        )

    async def preflight_query(self, plan_id: str) -> PreflightResponse:
        principal = self.principals.current()
        fingerprint = self.tickets.principal_fingerprint(principal)
        envelope = self._get_owned_plan(plan_id, fingerprint)
        plan = envelope.plan
        if plan.status != "prepared":
            raise ServiceError(f"plan must be prepared; status={plan.status}")
        if plan.expires_at <= datetime.now(UTC):
            raise ServiceError("plan has expired")
        if plan.policy_version != self.policy_config.version:
            raise ServiceError("policy changed after plan preparation; prepare a new plan")

        try:
            decisions = self.policy.enforce(principal, plan.compiled)
            explain = await self.database.preflight(
                plan.compiled, principal, self.policy_config.limits
            )
        except Exception as exc:
            logger.exception("preflight failed for plan %s", plan_id)
            try:
                self.store.reject_plan(plan_id)
            except StoreError:
                pass
            self.store.append_audit_event(
                event_type="plan.preflight_failed",
                actor_fingerprint=fingerprint,
                plan_id=plan_id,
                details=safe_error_details(exc),
            )
            raise ServiceError(str(exc)) from exc

        preflight_decisions = list(decisions)
        preflight_decisions.extend(self._explain_decisions(plan, explain))
        denied = [
            decision for decision in preflight_decisions if decision.outcome == PolicyOutcome.DENY
        ]
        if denied:
            self.store.reject_plan(plan_id)
            self.store.append_audit_event(
                event_type="plan.preflight_rejected",
                actor_fingerprint=fingerprint,
                plan_id=plan_id,
                details={
                    "explain": explain.model_dump(mode="json"),
                    "decisions": [decision.model_dump(mode="json") for decision in denied],
                },
            )
            raise PreflightRejected(
                "; ".join(decision.message for decision in denied),
                preflight_decisions,
            )

        effective_max_rows = min(plan.intent.limit, self.policy_config.limits.max_rows)
        token, claims = self.tickets.issue(
            plan,
            principal,
            ttl_seconds=self.policy_config.limits.ticket_ttl_seconds,
            max_rows=effective_max_rows,
            # Bind execution to the plan that was actually approved, not only to
            # the broader policy ceiling. Any upward planner drift requires a new plan.
            max_estimated_rows=explain.plan_rows,
            max_total_cost=explain.total_cost,
        )
        approved_plan = self.store.approve_plan(
            plan_id,
            explain=explain,
            ticket_jti=claims.jti,
            policy_decisions=preflight_decisions,
        )
        self.store.append_audit_event(
            event_type="plan.approved",
            actor_fingerprint=fingerprint,
            plan_id=plan_id,
            details={
                "ticket_jti_hash": sha256_json(claims.jti),
                "ticket_expires_at": claims.expires_at,
                "statement_hash": approved_plan.compiled.statement_hash,
                "max_rows": claims.max_rows,
                "max_estimated_rows": claims.max_estimated_rows,
                "max_total_cost": claims.max_total_cost,
                "explain": explain.model_dump(mode="json"),
                "policy_decision_codes": [d.code for d in preflight_decisions],
            },
        )
        return PreflightResponse(
            plan_id=plan_id,
            status="approved",
            ticket=token,
            ticket_expires_at=datetime.fromtimestamp(claims.expires_at, tz=UTC),
            explain=explain,
            policy_decisions=preflight_decisions,
        )

    async def execute_approved_query(self, ticket: str) -> QueryReceipt:
        principal = self.principals.current()
        fingerprint = self.tickets.principal_fingerprint(principal)
        try:
            preliminary_claims = self.tickets.verify(
                ticket,
                principal=principal,
                expected_policy_version=self.policy_config.version,
            )
            envelope = self._get_owned_plan(preliminary_claims.plan_id, fingerprint)
            claims = self.tickets.verify(
                ticket,
                principal=principal,
                expected_plan=envelope.plan,
                expected_policy_version=self.policy_config.version,
            )
            consumed = self.store.consume_plan(claims.plan_id, ticket_jti=claims.jti)
        except (TicketError, StoreError, PlanStateError, AccessDenied) as exc:
            self.store.append_audit_event(
                event_type="execution.ticket_rejected",
                actor_fingerprint=fingerprint,
                details=safe_error_details(exc),
            )
            raise AccessDenied(str(exc)) from exc

        execution = self.store.create_execution(consumed.plan.plan_id)
        self.store.append_audit_event(
            event_type="execution.started",
            actor_fingerprint=fingerprint,
            plan_id=consumed.plan.plan_id,
            execution_id=execution.execution_id,
            details={
                "statement_hash": consumed.plan.compiled.statement_hash,
                "ticket_jti_hash": sha256_json(claims.jti),
            },
        )

        try:
            recompiled = self.catalog.compile(
                consumed.plan.intent,
                principal,
                max_rows=self.policy_config.limits.max_rows,
                max_parameters=self.policy_config.limits.max_bind_parameters,
            )
            if recompiled.statement_hash != consumed.plan.compiled.statement_hash:
                raise ServiceError(
                    "stored plan no longer matches its structured intent and semantic catalog"
                )
            recomputed_statement_hash = sha256_json(
                {
                    "sql": consumed.plan.compiled.sql,
                    "parameters": consumed.plan.compiled.parameters,
                    "parameter_types": consumed.plan.compiled.parameter_types,
                    "semantic_binding": consumed.plan.compiled.semantic_binding.model_dump(
                        mode="json"
                    ),
                }
            )
            if recomputed_statement_hash != consumed.plan.compiled.statement_hash:
                raise ServiceError("stored plan statement hash failed recomputation")
            runtime_policy_decisions = self.policy.enforce(principal, consumed.plan.compiled)

            result = await self.database.execute(
                consumed.plan.compiled,
                principal,
                max_rows=claims.max_rows,
                max_total_cost=claims.max_total_cost,
                max_estimated_rows=claims.max_estimated_rows,
                expected_relations=consumed.plan.compiled.semantic_binding.source_tables,
                statement_timeout_ms=self.policy_config.limits.statement_timeout_ms,
            )
            if not result.transaction_read_only:
                raise ServiceError("database did not confirm a read-only transaction")
            if not result.explain.transaction_read_only:
                raise ServiceError("execution-time EXPLAIN was not produced read-only")
            if result.explain.total_cost > claims.max_total_cost:
                raise ServiceError("execution-time EXPLAIN cost exceeds signed ticket cap")
            if result.explain.plan_rows > claims.max_estimated_rows:
                raise ServiceError("execution-time EXPLAIN row estimate exceeds signed ticket cap")
            expected_relations = set(consumed.plan.compiled.semantic_binding.source_tables)
            if set(result.explain.relation_names) != expected_relations:
                raise ServiceError(
                    "execution-time EXPLAIN relations differ from semantic provenance"
                )
            if len(result.rows) > claims.max_rows:
                raise ServiceError("database gateway returned more rows than the ticket cap")
            if (
                result.explain.database_user != result.database_user
                or result.explain.database_name != result.database_name
            ):
                raise ServiceError("database identity evidence is internally inconsistent")
            preflight_database_user = consumed.explain.database_user if consumed.explain else None
            preflight_database_name = consumed.explain.database_name if consumed.explain else None
            if (
                preflight_database_user != result.database_user
                or preflight_database_name != result.database_name
            ):
                raise ServiceError("database identity changed between preflight and execution")

            metric = self.catalog.metric_definition(consumed.plan.intent.metric)
            status, checks, warnings = self.verifier.verify(
                result.rows, metric, truncated=result.truncated
            )
            checks = [
                VerificationCheck(name="ticket_signature_and_binding", passed=True),
                VerificationCheck(name="statement_hash_binding", passed=True),
                VerificationCheck(name="structured_intent_recompiled", passed=True),
                VerificationCheck(name="statement_hash_recomputed", passed=True),
                VerificationCheck(
                    name="policy_revalidated_at_execution",
                    passed=True,
                    details={
                        "policy_version": self.policy_config.version,
                        "decision_codes": [decision.code for decision in runtime_policy_decisions],
                    },
                ),
                VerificationCheck(
                    name="database_identity_stable",
                    passed=True,
                    details={
                        "database_user": result.database_user,
                        "database_name": result.database_name,
                    },
                ),
                VerificationCheck(
                    name="returned_rows_within_ticket_cap",
                    passed=True,
                    details={
                        "returned_rows": len(result.rows),
                        "ticket_cap": claims.max_rows,
                    },
                ),
                VerificationCheck(
                    name="execution_time_explain_within_policy",
                    passed=True,
                    details={
                        "actual_cost": result.explain.total_cost,
                        "maximum_cost": claims.max_total_cost,
                        "actual_max_plan_rows": result.explain.plan_rows,
                        "maximum_plan_rows": claims.max_estimated_rows,
                    },
                ),
                VerificationCheck(
                    name="execution_time_relations_match_semantic_binding",
                    passed=True,
                    details={"relations": result.explain.relation_names},
                ),
                *checks,
            ]
            result_digest = sha256_json(result.rows)
            receipt = QueryReceipt(
                status=status,
                execution_id=execution.execution_id,
                answer=result.rows,
                row_count=len(result.rows),
                semantic=SemanticEvidence(binding=consumed.plan.compiled.semantic_binding),
                authorization=AuthorizationEvidence(
                    user_id=principal.user_id,
                    roles=principal.roles,
                    tenant_scope=principal.tenant_id,
                    principal_fingerprint=fingerprint,
                    policy_version=self.policy_config.version,
                    decisions=runtime_policy_decisions,
                ),
                safety=SafetyEvidence(
                    ast_validated=True,
                    single_statement=True,
                    structured_intent_recompiled=True,
                    statement_hash_recomputed=True,
                    policy_revalidated_at_execution=True,
                    read_only_transaction=result.transaction_read_only,
                    database_user=result.database_user,
                    database_name=result.database_name,
                    database_identity_matches_preflight=True,
                    preflight_explain_total_cost=(
                        consumed.explain.total_cost if consumed.explain else 0.0
                    ),
                    preflight_explain_plan_rows=(
                        consumed.explain.plan_rows if consumed.explain else 0
                    ),
                    explain_total_cost=result.explain.total_cost,
                    explain_plan_rows=result.explain.plan_rows,
                    relations_rechecked_in_execution_transaction=True,
                    statement_timeout_ms=self.policy_config.limits.statement_timeout_ms,
                    max_rows=claims.max_rows,
                    truncated=result.truncated,
                ),
                verification=checks,
                provenance=ProvenanceEvidence(
                    plan_id=consumed.plan.plan_id,
                    execution_id=execution.execution_id,
                    query_hash=consumed.plan.compiled.statement_hash,
                    metric=consumed.plan.compiled.semantic_binding.metric,
                    metric_version=consumed.plan.compiled.semantic_binding.metric_version,
                    semantic_catalog_version=(
                        consumed.plan.compiled.semantic_binding.semantic_catalog_version
                    ),
                    source_tables=consumed.plan.compiled.semantic_binding.source_tables,
                    source_columns=consumed.plan.compiled.semantic_binding.source_columns,
                    snapshot_time=result.snapshot_time,
                    result_digest=result_digest,
                ),
                warnings=warnings,
            )
            self.store.complete_execution(execution.execution_id, query_receipt=receipt)
            self.store.complete_plan(consumed.plan.plan_id, succeeded=True)
            receipt_without_rows = redacted_query_receipt(receipt)
            self.store.append_audit_event(
                event_type="execution.completed",
                actor_fingerprint=fingerprint,
                plan_id=consumed.plan.plan_id,
                execution_id=execution.execution_id,
                details={
                    "status": receipt.status,
                    "row_count": receipt.row_count,
                    "truncated": result.truncated,
                    "result_digest": result_digest,
                    "query_receipt_digest_without_rows": sha256_json(receipt_without_rows),
                },
            )
            return receipt
        except Exception as exc:
            logger.exception(
                "execution failed for plan %s and execution %s",
                consumed.plan.plan_id,
                execution.execution_id,
            )
            error_info = public_error_info(exc)
            self.store.complete_execution(execution.execution_id, error=error_info.code)
            self.store.complete_plan(consumed.plan.plan_id, succeeded=False)
            self.store.append_audit_event(
                event_type="execution.failed",
                actor_fingerprint=fingerprint,
                plan_id=consumed.plan.plan_id,
                execution_id=execution.execution_id,
                details=safe_error_details(exc),
            )
            raise ServiceError(str(exc)) from exc

    def get_audit_evidence(self, execution_id: str) -> AuditEvidence:
        principal = self.principals.current()
        fingerprint = self.tickets.principal_fingerprint(principal)
        execution = self.store.get_execution(execution_id)
        self._get_owned_plan(execution.plan_id, fingerprint)
        events = self.store.get_audit_events(plan_id=execution.plan_id)
        chain_valid, event_count = self.store.verify_audit_chain()
        return AuditEvidence(
            execution_id=execution_id,
            plan_id=execution.plan_id,
            event_chain=events,
            chain_valid=chain_valid,
            global_chain_event_count=event_count,
            query_receipt_without_rows=execution.evidence,
        )

    def _get_owned_plan(self, plan_id: str, fingerprint: str) -> StoredPlanEnvelope:
        envelope = self.store.get_plan(plan_id)
        if envelope.plan.principal_fingerprint != fingerprint:
            raise AccessDenied("plan belongs to a different principal")
        return envelope

    def _metric_visible(self, roles: list[str], metric_name: str) -> bool:
        import fnmatch

        patterns = [
            pattern
            for role in roles
            if role in self.policy_config.roles
            for pattern in self.policy_config.roles[role].allow_metrics
        ]
        return any(fnmatch.fnmatchcase(metric_name, pattern) for pattern in patterns)

    def _explain_decisions(
        self, plan: PreparedPlan, explain: ExplainEvidence
    ) -> list[PolicyDecision]:
        limits = self.policy_config.limits
        decisions: list[PolicyDecision] = []
        decisions.append(
            PolicyDecision(
                code="db.transaction_read_only",
                outcome=(
                    PolicyOutcome.ALLOW if explain.transaction_read_only else PolicyOutcome.DENY
                ),
                message=(
                    "database confirmed a read-only transaction"
                    if explain.transaction_read_only
                    else "database did not confirm a read-only transaction"
                ),
                evidence={"database_user": explain.database_user},
            )
        )
        decisions.append(
            PolicyDecision(
                code="db.cost_guard",
                outcome=(
                    PolicyOutcome.ALLOW
                    if explain.total_cost <= limits.max_total_cost
                    else PolicyOutcome.DENY
                ),
                message=(
                    f"estimated total cost {explain.total_cost} "
                    f"{'is within' if explain.total_cost <= limits.max_total_cost else 'exceeds'} policy"
                ),
                evidence={
                    "actual": explain.total_cost,
                    "maximum": limits.max_total_cost,
                },
            )
        )
        decisions.append(
            PolicyDecision(
                code="db.estimated_rows_guard",
                outcome=(
                    PolicyOutcome.ALLOW
                    if explain.plan_rows <= limits.max_estimated_rows
                    else PolicyOutcome.DENY
                ),
                message=(
                    f"estimated rows {explain.plan_rows} "
                    f"{'is within' if explain.plan_rows <= limits.max_estimated_rows else 'exceeds'} policy"
                ),
                evidence={
                    "actual": explain.plan_rows,
                    "maximum": limits.max_estimated_rows,
                },
            )
        )
        actual_relations = set(explain.relation_names)
        expected_relations = set(plan.compiled.semantic_binding.source_tables)
        decisions.append(
            PolicyDecision(
                code="db.explain_relations_match",
                outcome=(
                    PolicyOutcome.ALLOW
                    if actual_relations == expected_relations
                    else PolicyOutcome.DENY
                ),
                message=(
                    "EXPLAIN relations match semantic provenance"
                    if actual_relations == expected_relations
                    else "EXPLAIN relations differ from semantic provenance"
                ),
                evidence={
                    "actual": sorted(actual_relations),
                    "expected": sorted(expected_relations),
                },
            )
        )
        return decisions
