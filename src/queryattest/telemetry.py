from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext
from typing import Any, cast


class Telemetry:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._tracer: Any = None
        if enabled:
            try:
                from opentelemetry import trace
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "OpenTelemetry is enabled but optional dependencies are missing; "
                    "install queryattest[otel]"
                ) from exc
            self._tracer = trace.get_tracer("queryattest")

    def span(
        self, name: str, attributes: dict[str, Any] | None = None
    ) -> AbstractContextManager[Any]:
        if not self.enabled:
            return nullcontext()
        return cast(
            AbstractContextManager[Any],
            self._tracer.start_as_current_span(name, attributes=attributes or {}),
        )
