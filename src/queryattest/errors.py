from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class PubliclyClassifiedError(Protocol):
    public_code: str
    public_message: str


@dataclass(frozen=True, slots=True)
class PublicErrorInfo:
    code: str
    message: str

    def render(self) -> str:
        return f"{self.code}: {self.message}"


def public_error_info(exc: BaseException) -> PublicErrorInfo:
    code = getattr(exc, "public_code", "internal_error")
    message = getattr(
        exc,
        "public_message",
        "The operation could not be completed. Consult server logs using the audit identifiers.",
    )
    return PublicErrorInfo(code=str(code), message=str(message))


def safe_error_details(exc: BaseException) -> dict[str, str]:
    info = public_error_info(exc)
    return {
        "error_code": info.code,
        "error_type": type(exc).__name__,
    }
