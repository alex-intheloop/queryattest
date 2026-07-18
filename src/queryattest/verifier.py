from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from queryattest.canonical import canonical_json
from queryattest.config import MetricDefinition, ResultCheckDefinition
from queryattest.models import VerificationCheck


class ResultVerifier:
    """Deterministic result checks declared alongside a versioned metric."""

    def verify(
        self,
        rows: list[dict[str, Any]],
        metric: MetricDefinition,
        *,
        truncated: bool,
    ) -> tuple[
        Literal["verified", "partially_verified", "failed"],
        list[VerificationCheck],
        list[str],
    ]:
        checks: list[VerificationCheck] = [
            VerificationCheck(
                name="execution_returned_structured_rows",
                passed=True,
                details={"row_count": len(rows)},
            )
        ]
        warnings: list[str] = []

        for definition in metric.checks:
            checks.append(self._evaluate_check(rows, definition))

        if truncated:
            warnings.append(
                "The result reached the requested row cap; verification checks apply only to the returned page."
            )

        failed = [check for check in checks if not check.passed]
        status: Literal["verified", "partially_verified", "failed"]
        if failed:
            status = "failed"
        elif truncated or not metric.checks:
            status = "partially_verified"
            if not metric.checks:
                warnings.append(
                    "No metric-specific result checks are configured; only execution, policy, and provenance were verified."
                )
        else:
            status = "verified"
        return status, checks, warnings

    def _evaluate_check(
        self, rows: list[dict[str, Any]], definition: ResultCheckDefinition
    ) -> VerificationCheck:
        check_type = definition.type
        if check_type == "row_count_min":
            expected = int(definition.value if definition.value is not None else 0)
            return VerificationCheck(
                name=f"row_count_min:{expected}",
                passed=len(rows) >= expected,
                details={"actual": len(rows), "expected_min": expected},
            )
        if check_type == "row_count_max":
            expected = int(definition.value if definition.value is not None else 0)
            return VerificationCheck(
                name=f"row_count_max:{expected}",
                passed=len(rows) <= expected,
                details={"actual": len(rows), "expected_max": expected},
            )

        if definition.field is None:
            raise ValueError(f"verification check {check_type} is missing its field")
        field = definition.field
        missing_rows = [index for index, row in enumerate(rows) if field not in row]
        if missing_rows:
            return VerificationCheck(
                name=f"{check_type}:{field}",
                passed=False,
                details={
                    "reason": "field_missing",
                    "missing_row_count": len(missing_rows),
                    "sample_row_indexes": missing_rows[:20],
                },
            )
        values = [row[field] for row in rows]

        if check_type == "non_null":
            null_indexes = [index for index, value in enumerate(values) if value is None]
            return VerificationCheck(
                name=f"non_null:{field}",
                passed=bool(rows) and not null_indexes,
                details={
                    "row_count": len(rows),
                    "null_count": len(null_indexes),
                    "sample_null_row_indexes": null_indexes[:20],
                },
            )
        if check_type == "unique":
            normalized = [canonical_json(value) for value in values]
            unique_count = len(set(normalized))
            return VerificationCheck(
                name=f"unique:{field}",
                passed=unique_count == len(values),
                details={"row_count": len(values), "unique_count": unique_count},
            )

        numeric_values: list[tuple[int, Decimal]] = []
        for index, value in enumerate(values):
            if value is None:
                return VerificationCheck(
                    name=f"{check_type}:{field}",
                    passed=False,
                    details={"reason": "null_numeric_value", "row_index": index},
                )
            try:
                converted = Decimal(str(value))
            except (InvalidOperation, ValueError):
                return VerificationCheck(
                    name=f"{check_type}:{field}",
                    passed=False,
                    details={
                        "reason": "non_numeric_value",
                        "row_index": index,
                        "value_type": type(value).__name__,
                    },
                )
            if not converted.is_finite():
                return VerificationCheck(
                    name=f"{check_type}:{field}",
                    passed=False,
                    details={"reason": "non_finite_numeric_value", "row_index": index},
                )
            numeric_values.append((index, converted))

        threshold = Decimal(str(definition.value))
        if check_type == "min":
            failing_indexes = [index for index, value in numeric_values if value < threshold]
            passed = bool(numeric_values) and not failing_indexes
            return VerificationCheck(
                name=f"min:{field}",
                passed=passed,
                details={
                    "threshold": str(threshold),
                    "failing_count": len(failing_indexes),
                    "sample_failing_row_indexes": failing_indexes[:20],
                },
            )
        if check_type == "max":
            failing_indexes = [index for index, value in numeric_values if value > threshold]
            passed = bool(numeric_values) and not failing_indexes
            return VerificationCheck(
                name=f"max:{field}",
                passed=passed,
                details={
                    "threshold": str(threshold),
                    "failing_count": len(failing_indexes),
                    "sample_failing_row_indexes": failing_indexes[:20],
                },
            )
        raise ValueError(f"unsupported verification check: {check_type}")
