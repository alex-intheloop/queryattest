from __future__ import annotations

import pytest
from pydantic import ValidationError

from queryattest.config import SemanticConfig
from queryattest.models import FilterSpec, QueryIntent, SortSpec
from queryattest.semantics import SemanticCatalog, SemanticError


def test_compiles_parameterized_tenant_scoped_metric(service) -> None:
    response = service.prepare_query(
        QueryIntent(
            question="Doanh thu tháng 6 theo kênh",
            metric="net_revenue",
            dimensions=["channel"],
            filters=[
                FilterSpec(
                    field="completed_at",
                    op="gte",
                    value="2026-06-01T00:00:00Z",
                )
            ],
            order_by=[SortSpec(field="net_revenue", direction="desc")],
            limit=100,
        )
    )

    assert "o.tenant_id = $1" in response.sql_template
    assert "o.completed_at >= $2" in response.sql_template
    assert response.sql_template.endswith("LIMIT 101")
    assert response.parameter_count == 2
    assert response.semantic_binding.metric_version == "3"
    assert "analytics.orders.status" in response.semantic_binding.source_columns
    assert "analytics.orders.tenant_id" in response.semantic_binding.source_columns


def test_unknown_dimension_is_rejected(service) -> None:
    with pytest.raises(Exception, match="unknown dimension"):
        service.prepare_query(
            QueryIntent(
                question="Revenue by secret dimension",
                metric="net_revenue",
                dimensions=["does_not_exist"],
            )
        )


def test_denied_sensitive_filter_is_rejected(service) -> None:
    with pytest.raises(Exception, match="explicitly denied"):
        service.prepare_query(
            QueryIntent(
                question="Revenue for one customer",
                metric="net_revenue",
                filters=[
                    FilterSpec(
                        field="customer_email",
                        op="eq",
                        value="a1@example.test",
                    )
                ],
            )
        )


def test_tenant_is_required(service) -> None:
    principal = service.principals.current()
    service.principals._principal = principal.model_copy(update={"tenant_id": None})
    with pytest.raises(Exception, match="tenant-scoped"):
        service.prepare_query(QueryIntent(question="Revenue", metric="net_revenue"))


def test_catalog_rejects_declared_provenance_that_does_not_match_expression(service) -> None:
    raw = service.catalog.config.model_dump(mode="python")
    raw["metrics"]["net_revenue"]["columns"] = ["completed_at"]
    config = SemanticConfig.model_validate(raw)
    with pytest.raises(SemanticError, match="provenance mismatch"):
        SemanticCatalog(config)


def test_filter_value_list_is_bounded() -> None:
    with pytest.raises(ValidationError, match="at most 100"):
        FilterSpec(field="country", op="in", value=[str(i) for i in range(101)])


def test_timestamp_filter_requires_an_explicit_utc_offset(service) -> None:
    with pytest.raises(Exception, match="UTC offset"):
        service.prepare_query(
            QueryIntent(
                question="Revenue after a local timestamp",
                metric="net_revenue",
                filters=[
                    FilterSpec(
                        field="completed_at",
                        op="gte",
                        value="2026-07-18T09:00:00",
                    )
                ],
            )
        )
