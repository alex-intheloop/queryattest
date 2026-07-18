from __future__ import annotations

from queryattest.models import QueryIntent
from queryattest.policy import PolicyOutcome


def _compiled(service):
    response = service.prepare_query(QueryIntent(question="Count orders", metric="order_count"))
    return service.store.get_plan(response.plan_id).plan.compiled


def test_valid_metric_query_passes_policy(service) -> None:
    compiled = _compiled(service)
    report = service.policy.evaluate(service.principals.current(), compiled)
    assert report.allowed
    assert not [d for d in report.decisions if d.outcome == PolicyOutcome.DENY]


def test_multi_statement_is_rejected(service) -> None:
    compiled = _compiled(service)
    modified = compiled.model_copy(update={"sql": compiled.sql + "; DELETE FROM analytics.orders"})
    report = service.policy.evaluate(service.principals.current(), modified)
    assert not report.allowed
    assert any(d.code == "sql.multiple_statements" for d in report.decisions)


def test_select_star_is_rejected(service) -> None:
    compiled = _compiled(service)
    modified = compiled.model_copy(update={"sql": "SELECT * FROM analytics.orders AS o LIMIT 2"})
    report = service.policy.evaluate(service.principals.current(), modified)
    assert not report.allowed
    assert any(d.code == "sql.select_star_denied" for d in report.decisions)


def test_extra_relation_is_rejected(service) -> None:
    compiled = _compiled(service)
    modified = compiled.model_copy(
        update={
            "sql": (
                "SELECT COUNT(o.order_id) AS order_count "
                "FROM analytics.orders AS o, analytics.orders AS x LIMIT 2"
            )
        }
    )
    report = service.policy.evaluate(service.principals.current(), modified)
    assert not report.allowed
    assert any(d.code == "sql.tables_mismatch_binding" for d in report.decisions)


def test_missing_tenant_predicate_is_rejected_by_exact_column_provenance(service) -> None:
    compiled = _compiled(service)
    modified = compiled.model_copy(
        update={"sql": compiled.sql.replace(" WHERE o.tenant_id = $1", "")}
    )
    report = service.policy.evaluate(service.principals.current(), modified)
    assert not report.allowed
    mismatch = next(
        decision for decision in report.decisions if decision.code == "sql.columns_mismatch_binding"
    )
    assert "analytics.orders.tenant_id" in mismatch.evidence["missing"]
