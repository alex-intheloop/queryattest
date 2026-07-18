from __future__ import annotations

from typing import Protocol

from queryattest.config import AppSettings
from queryattest.models import Principal


class PrincipalProvider(Protocol):
    def current(self) -> Principal: ...


class EnvironmentPrincipalProvider:
    """Immutable identity source for local/stdio MCP deployments."""

    def __init__(self, settings: AppSettings) -> None:
        self._principal = Principal(
            user_id=settings.user_id,
            roles=settings.role_list,
            tenant_id=settings.tenant_id,
            source="environment",
        )

    def current(self) -> Principal:
        return self._principal.model_copy(deep=True)
