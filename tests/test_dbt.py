from __future__ import annotations

import json

from queryattest.config import load_semantics
from queryattest.dbt import import_dbt_manifest


def test_dbt_importer_writes_a_strict_loadable_catalog(tmp_path) -> None:
    manifest_path = tmp_path / "manifest.json"
    output_path = tmp_path / "semantics.yaml"
    manifest_path.write_text(
        json.dumps(
            {
                "metadata": {"dbt_version": "1.10.0"},
                "nodes": {
                    "model.demo.orders": {
                        "resource_type": "model",
                        "name": "orders",
                        "schema": "analytics",
                        "alias": "orders",
                        "description": "Order model",
                        "columns": {
                            "tenant_id": {"data_type": "varchar"},
                            "completed_at": {"data_type": "timestamp"},
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = import_dbt_manifest(manifest_path, output_path, tenant_column="tenant_id")
    loaded = load_semantics(output_path)

    assert result["warnings"] == []
    assert loaded.data_products["orders"].table == "analytics.orders"
    assert loaded.metrics == {}
