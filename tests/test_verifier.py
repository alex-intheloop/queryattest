from __future__ import annotations

from queryattest.verifier import ResultVerifier


def test_metric_checks_produce_verified_status(service) -> None:
    metric = service.catalog.metric_definition("net_revenue")
    status, checks, warnings = ResultVerifier().verify(
        [{"net_revenue": "10.00"}], metric, truncated=False
    )
    assert status == "verified"
    assert all(check.passed for check in checks)
    assert warnings == []


def test_failed_check_marks_receipt_failed(service) -> None:
    metric = service.catalog.metric_definition("net_revenue")
    status, checks, _ = ResultVerifier().verify([{"net_revenue": "-1.00"}], metric, truncated=False)
    assert status == "failed"
    assert any(not check.passed for check in checks)
