from __future__ import annotations

from typing import Any

import pytest

from queryattest.config import ResultCheckDefinition
from queryattest.verifier import ResultVerifier


def metric_with_checks(service: Any, checks: list[ResultCheckDefinition]):
    metric = service.catalog.metric_definition("net_revenue")
    return metric.model_copy(update={"checks": checks})


def test_no_metric_checks_and_truncation_are_partially_verified(service: Any) -> None:
    metric = metric_with_checks(service, [])
    status, _, warnings = ResultVerifier().verify([{"net_revenue": "1"}], metric, truncated=True)
    assert status == "partially_verified"
    assert len(warnings) == 2


@pytest.mark.parametrize(
    ("check", "rows", "passed"),
    [
        (ResultCheckDefinition(type="row_count_min", value=2), [{}, {}], True),
        (ResultCheckDefinition(type="row_count_max", value=1), [{}, {}], False),
        (
            ResultCheckDefinition(type="unique", field="net_revenue"),
            [{"net_revenue": 1}, {"net_revenue": 1}],
            False,
        ),
        (
            ResultCheckDefinition(type="non_null", field="net_revenue"),
            [{"net_revenue": None}],
            False,
        ),
        (
            ResultCheckDefinition(type="max", field="net_revenue", value=10),
            [{"net_revenue": 11}],
            False,
        ),
        (
            ResultCheckDefinition(type="min", field="net_revenue", value=0),
            [{"net_revenue": "NaN"}],
            False,
        ),
    ],
)
def test_all_verifier_check_families(
    service: Any,
    check: ResultCheckDefinition,
    rows: list[dict[str, Any]],
    passed: bool,
) -> None:
    metric = metric_with_checks(service, [check])
    _, checks, _ = ResultVerifier().verify(rows, metric, truncated=False)
    assert checks[-1].passed is passed


def test_missing_and_non_numeric_fields_fail_without_value_echo(service: Any) -> None:
    verifier = ResultVerifier()
    missing_metric = metric_with_checks(
        service, [ResultCheckDefinition(type="min", field="net_revenue", value=0)]
    )
    _, checks, _ = verifier.verify([{"other": "secret"}], missing_metric, truncated=False)
    assert checks[-1].details["reason"] == "field_missing"

    _, checks, _ = verifier.verify([{"net_revenue": object()}], missing_metric, truncated=False)
    assert checks[-1].details == {
        "reason": "non_numeric_value",
        "row_index": 0,
        "value_type": "object",
    }


def test_invalid_internal_check_definition_is_rejected(service: Any) -> None:
    verifier = ResultVerifier()
    malformed = ResultCheckDefinition.model_construct(type="min", field=None, value=0)
    with pytest.raises(ValueError, match="missing its field"):
        verifier._evaluate_check([], malformed)

    unsupported = ResultCheckDefinition.model_construct(
        type="unsupported", field="net_revenue", value=0
    )
    with pytest.raises(ValueError, match="unsupported"):
        verifier._evaluate_check([{"net_revenue": 1}], unsupported)
