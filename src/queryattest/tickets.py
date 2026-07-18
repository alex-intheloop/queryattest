from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from queryattest.canonical import canonical_json
from queryattest.crypto import KeyMaterial
from queryattest.models import PreparedPlan, Principal, TicketClaims


class TicketError(PermissionError):
    """Raised when an execution ticket is invalid or context-bound incorrectly."""

    public_code = "execution_ticket_rejected"
    public_message = (
        "The execution ticket is invalid, expired, already used, or context-bound differently."
    )


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url encoding") from exc
    if _b64encode(decoded) != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _decode_canonical_json_object(encoded: str) -> dict[str, Any]:
    raw = _b64decode(encoded)
    decoded = json.loads(raw, object_pairs_hook=_json_object_no_duplicates)
    if not isinstance(decoded, dict):
        raise ValueError("ticket segment must contain a JSON object")
    canonical_encoded = _b64encode(canonical_json(decoded).encode("utf-8"))
    if not hmac.compare_digest(canonical_encoded, encoded):
        raise ValueError("ticket JSON is not canonical")
    return decoded


class TicketService:
    MAX_TOKEN_LENGTH = 16_384

    def __init__(
        self,
        secret: str | bytes | KeyMaterial,
        *,
        issuer: str = "queryattest",
        audience: str = "queryattest-executor",
        clock: Callable[[], float] = time.time,
        max_ttl_seconds: int = 3600,
        clock_skew_seconds: int = 30,
    ) -> None:
        normalized_issuer = issuer.strip()
        normalized_audience = audience.strip()
        if not normalized_issuer or len(normalized_issuer) > 128:
            raise ValueError("ticket issuer must contain between 1 and 128 characters")
        if not normalized_audience or len(normalized_audience) > 128:
            raise ValueError("ticket audience must contain between 1 and 128 characters")
        if max_ttl_seconds < 1:
            raise ValueError("maximum ticket ttl must be positive")
        if clock_skew_seconds < 0:
            raise ValueError("ticket clock skew may not be negative")

        self._keys = secret if isinstance(secret, KeyMaterial) else KeyMaterial.from_secret(secret)
        self.issuer = normalized_issuer
        self.audience = normalized_audience
        self._clock = clock
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    @property
    def key_id(self) -> str:
        return self._keys.key_id

    def issue(
        self,
        plan: PreparedPlan,
        principal: Principal,
        *,
        ttl_seconds: int,
        max_rows: int,
        max_estimated_rows: int,
        max_total_cost: float,
    ) -> tuple[str, TicketClaims]:
        if not 1 <= ttl_seconds <= self.max_ttl_seconds:
            raise ValueError(f"ticket ttl must be between 1 and {self.max_ttl_seconds} seconds")
        if max_rows < 1:
            raise ValueError("ticket row cap must be positive")
        if max_estimated_rows < 0:
            raise ValueError("ticket estimated-row cap may not be negative")
        if max_total_cost < 0:
            raise ValueError("ticket cost cap may not be negative")

        now = int(self._clock())
        fingerprint = self.principal_fingerprint(principal)
        if fingerprint != plan.principal_fingerprint:
            raise TicketError("cannot issue a ticket for a principal different from the plan owner")
        claims = TicketClaims(
            jti=str(uuid4()),
            issuer=self.issuer,
            audience=self.audience,
            subject=self.context_digest("subject", plan.principal_fingerprint),
            plan_id=plan.plan_id,
            statement_hash=plan.compiled.statement_hash,
            principal_fingerprint=plan.principal_fingerprint,
            tenant_hash=(
                self.context_digest("tenant", principal.tenant_id) if principal.tenant_id else None
            ),
            roles_hash=self.context_digest("roles", canonical_json(sorted(principal.roles))),
            policy_version=plan.policy_version,
            issued_at=now,
            expires_at=now + ttl_seconds,
            max_rows=max_rows,
            max_estimated_rows=max_estimated_rows,
            max_total_cost=max_total_cost,
        )
        header = {"alg": "HS256", "kid": self.key_id, "typ": "QAT", "v": 2}
        encoded_header = _b64encode(canonical_json(header).encode("utf-8"))
        encoded_payload = _b64encode(canonical_json(claims.model_dump(mode="json")).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._keys.ticket_signing_key, signing_input, hashlib.sha256).digest()
        token = f"{encoded_header}.{encoded_payload}.{_b64encode(signature)}"
        if len(token) > self.MAX_TOKEN_LENGTH:  # defensive invariant for future claim additions
            raise ValueError("issued execution ticket exceeds the maximum token length")
        return token, claims

    def verify(
        self,
        token: str,
        *,
        principal: Principal,
        expected_plan: PreparedPlan | None = None,
        expected_policy_version: str | None = None,
    ) -> TicketClaims:
        if not token or len(token) > self.MAX_TOKEN_LENGTH:
            raise TicketError("execution ticket length is invalid")
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise TicketError("malformed execution ticket") from exc

        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            self._keys.ticket_signing_key, signing_input, hashlib.sha256
        ).digest()
        try:
            supplied_signature = _b64decode(encoded_signature)
        except ValueError as exc:
            raise TicketError("invalid ticket signature encoding") from exc
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise TicketError("execution ticket signature is invalid")

        try:
            header = _decode_canonical_json_object(encoded_header)
            payload = _decode_canonical_json_object(encoded_payload)
            claims = TicketClaims.model_validate(payload)
        except Exception as exc:
            raise TicketError("execution ticket payload is invalid") from exc
        if header != {"alg": "HS256", "kid": self.key_id, "typ": "QAT", "v": 2}:
            raise TicketError("unsupported execution ticket header or key identifier")

        now = int(self._clock())
        lifetime = claims.expires_at - claims.issued_at
        if lifetime <= 0 or lifetime > self.max_ttl_seconds:
            raise TicketError("execution ticket lifetime is invalid")
        if claims.issuer != self.issuer or claims.audience != self.audience:
            raise TicketError("execution ticket issuer or audience mismatch")
        if claims.expires_at <= now:
            raise TicketError("execution ticket has expired")
        if claims.issued_at > now + self.clock_skew_seconds:
            raise TicketError("execution ticket was issued in the future")

        principal_fingerprint = self.principal_fingerprint(principal)
        if claims.principal_fingerprint != principal_fingerprint:
            raise TicketError("execution ticket is bound to a different principal")
        expected_subject = self.context_digest("subject", principal_fingerprint)
        if claims.subject != expected_subject:
            raise TicketError("execution ticket subject mismatch")
        expected_roles_hash = self.context_digest("roles", canonical_json(sorted(principal.roles)))
        if claims.roles_hash != expected_roles_hash:
            raise TicketError("execution ticket role binding mismatch")
        expected_tenant_hash = (
            self.context_digest("tenant", principal.tenant_id) if principal.tenant_id else None
        )
        if claims.tenant_hash != expected_tenant_hash:
            raise TicketError("execution ticket tenant binding mismatch")

        if expected_policy_version and claims.policy_version != expected_policy_version:
            raise TicketError("execution ticket was issued under a different policy version")
        if expected_plan:
            if claims.plan_id != expected_plan.plan_id:
                raise TicketError("execution ticket references a different plan")
            if claims.statement_hash != expected_plan.compiled.statement_hash:
                raise TicketError("execution ticket statement hash mismatch")
            if claims.policy_version != expected_plan.policy_version:
                raise TicketError("execution ticket plan policy mismatch")
        return claims

    def context_digest(self, label: str, value: str) -> str:
        return self._keys.context_digest(label, value)

    def principal_fingerprint(self, principal: Principal) -> str:
        return self.context_digest("principal", canonical_json(principal.model_dump(mode="json")))
