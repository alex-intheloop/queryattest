from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MIN_SECRET_BYTES = 32
_HKDF_SALT = b"queryattest/root-key/v1"


class KeyMaterialError(ValueError):
    """Raised when root key material is missing or too weak."""


def _secret_bytes(secret: str | bytes) -> bytes:
    raw = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(raw) < _MIN_SECRET_BYTES:
        raise KeyMaterialError(f"root secret must contain at least {_MIN_SECRET_BYTES} bytes")
    return raw


def _derive(secret: bytes, *, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=b"queryattest/" + purpose,
    ).derive(secret)


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    """Domain-separated keys derived from one operator-managed root secret."""

    ticket_signing_key: bytes
    context_hmac_key: bytes
    state_encryption_key: bytes
    key_id: str

    @classmethod
    def from_secret(cls, secret: str | bytes) -> KeyMaterial:
        root = _secret_bytes(secret)
        signing = _derive(root, purpose=b"ticket-signing/v1")
        context = _derive(root, purpose=b"context-hmac/v1")
        state = _derive(root, purpose=b"state-encryption/v1")
        key_id = hashlib.sha256(signing).hexdigest()[:16]
        return cls(
            ticket_signing_key=signing,
            context_hmac_key=context,
            state_encryption_key=state,
            key_id=key_id,
        )

    def context_digest(self, label: str, value: str) -> str:
        payload = f"queryattest-context-v1:{label}:{value}".encode()
        return hmac.new(self.context_hmac_key, payload, hashlib.sha256).hexdigest()
