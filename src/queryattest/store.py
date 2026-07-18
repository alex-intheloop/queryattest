from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field

from queryattest.canonical import canonical_json, sha256_json
from queryattest.crypto import KeyMaterial
from queryattest.models import (
    ExplainEvidence,
    PolicyDecision,
    PreparedPlan,
    QueryReceipt,
    StrictModel,
)


class StoreError(RuntimeError):
    public_code = "state_store_error"
    public_message = "The execution state could not be read or updated."


class PlanStateError(StoreError):
    public_code = "plan_state_rejected"
    public_message = "The plan is expired, already consumed, or not in an executable state."


class StoredPlanEnvelope(StrictModel):
    plan: PreparedPlan
    explain: ExplainEvidence | None = None
    ticket_jti: str | None = None
    consumed_at: datetime | None = None


class ExecutionRecord(StrictModel):
    execution_id: str
    plan_id: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


_IDENTITY_KEYS = {"roles", "unknown_roles", "user_id", "tenant_id", "tenant_scope"}


def _redact_identity_values(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key in _IDENTITY_KEYS:
                redacted[key] = ["[redacted]"] if isinstance(item, list) else "[redacted]"
            else:
                redacted[key] = _redact_identity_values(item)
        return redacted
    if isinstance(value, list):
        return [_redact_identity_values(item) for item in value]
    return value


def redacted_query_receipt(query_receipt: QueryReceipt) -> dict[str, Any]:
    """Return the persistable receipt view without result rows or raw identity values."""
    redacted = _redact_identity_values(query_receipt.model_dump(mode="json"))
    if not isinstance(redacted, dict):  # defensive invariant for future model changes
        raise StoreError("query receipt did not serialize to an object")
    evidence: dict[str, Any] = redacted
    evidence["answer"] = []
    evidence["answer_rows_redacted"] = True
    authorization = evidence.get("authorization")
    if isinstance(authorization, dict):
        authorization["identity_values_redacted"] = True
    return evidence


class EncryptedStateStore:
    """Encrypted plan state plus a tamper-evident, hash-chained audit log."""

    def __init__(self, path: Path, secret: str | bytes | KeyMaterial) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._keys = secret if isinstance(secret, KeyMaterial) else KeyMaterial.from_secret(secret)
        self._cipher = AESGCM(self._keys.state_encryption_key)
        self._initialize()
        self._restrict_state_file_permissions()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 10000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _restrict_state_file_permissions(self) -> None:
        if os.name == "posix" and self.path.exists():
            os.chmod(self.path, 0o600)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS plans (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    statement_hash TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    principal_fingerprint TEXT NOT NULL,
                    encrypted_payload BLOB NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT,
                    FOREIGN KEY(plan_id) REFERENCES plans(id)
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_fingerprint TEXT NOT NULL,
                    plan_id TEXT,
                    execution_id TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_plan ON audit_events(plan_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_events(execution_id, sequence);
                """
            )

    def put_plan(self, plan: PreparedPlan) -> None:
        envelope = StoredPlanEnvelope(plan=plan)
        encrypted = self._encrypt(plan.plan_id, envelope)
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO plans(
                    id, status, expires_at, statement_hash, policy_version,
                    principal_fingerprint, encrypted_payload, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.status,
                    plan.expires_at.isoformat(),
                    plan.compiled.statement_hash,
                    plan.policy_version,
                    plan.principal_fingerprint,
                    encrypted,
                    now,
                ),
            )

    def get_plan(self, plan_id: str) -> StoredPlanEnvelope:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT encrypted_payload FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
        if row is None:
            raise StoreError(f"unknown plan: {plan_id}")
        return self._decrypt(plan_id, row["encrypted_payload"])

    def approve_plan(
        self,
        plan_id: str,
        *,
        explain: ExplainEvidence,
        ticket_jti: str,
        policy_decisions: list[PolicyDecision] | None = None,
    ) -> PreparedPlan:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT encrypted_payload FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown plan: {plan_id}")
            envelope = self._decrypt(plan_id, row["encrypted_payload"])
            if envelope.plan.status != "prepared":
                raise PlanStateError(
                    f"plan {plan_id} must be prepared, found {envelope.plan.status}"
                )
            update_fields: dict[str, Any] = {"status": "approved"}
            if policy_decisions is not None:
                update_fields["policy_decisions"] = policy_decisions
            updated_plan = envelope.plan.model_copy(update=update_fields)
            updated = envelope.model_copy(
                update={"plan": updated_plan, "explain": explain, "ticket_jti": ticket_jti}
            )
            self._update_plan_row(connection, updated)
            connection.commit()
            return updated_plan

    def reject_plan(self, plan_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT encrypted_payload FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown plan: {plan_id}")
            envelope = self._decrypt(plan_id, row["encrypted_payload"])
            if envelope.plan.status != "prepared":
                raise PlanStateError(
                    f"plan {plan_id} must be prepared, found {envelope.plan.status}"
                )
            rejected = envelope.plan.model_copy(update={"status": "rejected"})
            self._update_plan_row(connection, envelope.model_copy(update={"plan": rejected}))
            connection.commit()

    def consume_plan(self, plan_id: str, *, ticket_jti: str) -> StoredPlanEnvelope:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT encrypted_payload FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown plan: {plan_id}")
            envelope = self._decrypt(plan_id, row["encrypted_payload"])
            if envelope.plan.status != "approved":
                raise PlanStateError(
                    f"plan {plan_id} is not executable; status={envelope.plan.status}"
                )
            if envelope.ticket_jti != ticket_jti:
                raise PlanStateError("ticket identifier does not match approved plan")
            if envelope.plan.expires_at <= now:
                expired_plan = envelope.plan.model_copy(update={"status": "expired"})
                self._update_plan_row(
                    connection, envelope.model_copy(update={"plan": expired_plan})
                )
                connection.commit()
                raise PlanStateError(f"plan {plan_id} has expired")
            executing_plan = envelope.plan.model_copy(update={"status": "executing"})
            consumed = envelope.model_copy(update={"plan": executing_plan, "consumed_at": now})
            self._update_plan_row(connection, consumed)
            connection.commit()
            return consumed

    def complete_plan(self, plan_id: str, *, succeeded: bool) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT encrypted_payload FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown plan: {plan_id}")
            envelope = self._decrypt(plan_id, row["encrypted_payload"])
            if envelope.plan.status != "executing":
                raise PlanStateError(
                    f"plan {plan_id} is not executing; status={envelope.plan.status}"
                )
            status = "executed" if succeeded else "failed"
            plan = envelope.plan.model_copy(update={"status": status})
            self._update_plan_row(connection, envelope.model_copy(update={"plan": plan}))
            connection.commit()

    def create_execution(self, plan_id: str) -> ExecutionRecord:
        record = ExecutionRecord(
            execution_id=str(uuid4()),
            plan_id=plan_id,
            status="running",
            created_at=datetime.now(UTC),
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO executions(
                    execution_id, plan_id, status, created_at, evidence_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.execution_id,
                    plan_id,
                    record.status,
                    record.created_at.isoformat(),
                    "{}",
                ),
            )
        return record

    def complete_execution(
        self,
        execution_id: str,
        *,
        query_receipt: QueryReceipt | None = None,
        error: str | None = None,
    ) -> None:
        completed_at = datetime.now(UTC)
        status = "succeeded" if query_receipt is not None else "failed"
        evidence: dict[str, Any] = {}
        if query_receipt is not None:
            evidence = redacted_query_receipt(query_receipt)
        with self._connect() as connection:
            updated = connection.execute(
                """
                UPDATE executions
                SET status = ?, completed_at = ?, evidence_json = ?, error = ?
                WHERE execution_id = ?
                """,
                (
                    status,
                    completed_at.isoformat(),
                    canonical_json(evidence),
                    error,
                    execution_id,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError(f"unknown execution: {execution_id}")

    def get_execution(self, execution_id: str) -> ExecutionRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()
        if row is None:
            raise StoreError(f"unknown execution: {execution_id}")
        return ExecutionRecord(
            execution_id=row["execution_id"],
            plan_id=row["plan_id"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            ),
            evidence=json.loads(row["evidence_json"]),
            error=row["error"],
        )

    def append_audit_event(
        self,
        *,
        event_type: str,
        actor_fingerprint: str,
        details: dict[str, Any],
        plan_id: str | None = None,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        timestamp = datetime.now(UTC).isoformat()
        event_id = str(uuid4())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else "GENESIS"
            event_body = {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "actor_fingerprint": actor_fingerprint,
                "plan_id": plan_id,
                "execution_id": execution_id,
                "details": details,
                "previous_hash": previous_hash,
            }
            event_hash = sha256_json(event_body)
            connection.execute(
                """
                INSERT INTO audit_events(
                    event_id, timestamp, event_type, actor_fingerprint,
                    plan_id, execution_id, details_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    event_type,
                    actor_fingerprint,
                    plan_id,
                    execution_id,
                    canonical_json(details),
                    previous_hash,
                    event_hash,
                ),
            )
            connection.commit()
        return {**event_body, "event_hash": event_hash}

    def get_audit_events(
        self, *, plan_id: str | None = None, execution_id: str | None = None
    ) -> list[dict[str, Any]]:
        parameters: tuple[str, ...]
        if plan_id and execution_id:
            sql = (
                "SELECT * FROM audit_events "
                "WHERE plan_id = ? AND execution_id = ? ORDER BY sequence"
            )
            parameters = (plan_id, execution_id)
        elif plan_id:
            sql = "SELECT * FROM audit_events WHERE plan_id = ? ORDER BY sequence"
            parameters = (plan_id,)
        elif execution_id:
            sql = "SELECT * FROM audit_events WHERE execution_id = ? ORDER BY sequence"
            parameters = (execution_id,)
        else:
            sql = "SELECT * FROM audit_events ORDER BY sequence"
            parameters = ()
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "actor_fingerprint": row["actor_fingerprint"],
                "plan_id": row["plan_id"],
                "execution_id": row["execution_id"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> tuple[bool, int]:
        events = self.get_audit_events()
        previous_hash = "GENESIS"
        for index, event in enumerate(events):
            event_body = {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "event_type": event["event_type"],
                "actor_fingerprint": event["actor_fingerprint"],
                "plan_id": event["plan_id"],
                "execution_id": event["execution_id"],
                "details": event["details"],
                "previous_hash": event["previous_hash"],
            }
            if event["previous_hash"] != previous_hash:
                return False, index
            if event["event_hash"] != sha256_json(event_body):
                return False, index
            previous_hash = event["event_hash"]
        return True, len(events)

    def _update_plan_row(
        self, connection: sqlite3.Connection, envelope: StoredPlanEnvelope
    ) -> None:
        encrypted = self._encrypt(envelope.plan.plan_id, envelope)
        connection.execute(
            """
            UPDATE plans SET status = ?, expires_at = ?, encrypted_payload = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                envelope.plan.status,
                envelope.plan.expires_at.isoformat(),
                encrypted,
                datetime.now(UTC).isoformat(),
                envelope.plan.plan_id,
            ),
        )

    def _encrypt(self, plan_id: str, envelope: StoredPlanEnvelope) -> bytes:
        nonce = os.urandom(12)
        plaintext = canonical_json(envelope.model_dump(mode="json")).encode("utf-8")
        ciphertext = self._cipher.encrypt(nonce, plaintext, plan_id.encode("utf-8"))
        return nonce + ciphertext

    def _decrypt(self, plan_id: str, blob: bytes) -> StoredPlanEnvelope:
        try:
            if len(blob) < 28:
                raise StoreError("encrypted plan payload is too short")
            nonce, ciphertext = blob[:12], blob[12:]
            plaintext = self._cipher.decrypt(nonce, ciphertext, plan_id.encode("utf-8"))
            envelope = StoredPlanEnvelope.model_validate_json(plaintext)
            if envelope.plan.plan_id != plan_id:
                raise StoreError("stored plan identifier does not match its database key")
            compiled = envelope.plan.compiled
            if len(compiled.parameters) != len(compiled.parameter_types):
                raise StoreError("stored plan parameter metadata is inconsistent")
            restored_parameters = [
                self._restore_parameter(value, parameter_type)
                for value, parameter_type in zip(
                    compiled.parameters, compiled.parameter_types, strict=True
                )
            ]
            restored_compiled = compiled.model_copy(update={"parameters": restored_parameters})
            restored_plan = envelope.plan.model_copy(update={"compiled": restored_compiled})
            return envelope.model_copy(update={"plan": restored_plan})
        except StoreError:
            raise
        except Exception as exc:
            raise StoreError(f"encrypted plan state failed authentication: {plan_id}") from exc

    @staticmethod
    def _restore_parameter(value: Any, parameter_type: str) -> Any:
        if parameter_type == "string":
            return str(value)
        if parameter_type == "integer":
            if isinstance(value, bool):
                raise StoreError("stored integer parameter is a boolean")
            return int(value)
        if parameter_type == "number":
            converted = Decimal(str(value))
            if not converted.is_finite():
                raise StoreError("stored numeric parameter is not finite")
            return converted
        if parameter_type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {"true", "false"}:
                return value.lower() == "true"
            raise StoreError("stored boolean parameter is invalid")
        if parameter_type == "date":
            if isinstance(value, datetime):
                return value.date()
            if isinstance(value, date):
                return value
            return date.fromisoformat(str(value))
        if parameter_type == "timestamp":
            if isinstance(value, datetime):
                converted_timestamp = value
            else:
                converted_timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if converted_timestamp.tzinfo is None or converted_timestamp.utcoffset() is None:
                raise StoreError("stored timestamp parameter is missing a UTC offset")
            return converted_timestamp
        if parameter_type == "uuid":
            if isinstance(value, UUID):
                return value
            return UUID(str(value))
        raise StoreError(f"unsupported stored parameter type: {parameter_type}")
