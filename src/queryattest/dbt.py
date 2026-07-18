from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from queryattest.config import IDENTIFIER_RE


def import_dbt_manifest(
    manifest_path: Path,
    output_path: Path,
    *,
    tenant_column: str | None = None,
) -> dict[str, Any]:
    """Create a conservative semantic-catalog stub from dbt model metadata.

    Metric expressions are intentionally not guessed. Operators must add and review them.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    nodes = manifest.get("nodes", {})
    data_products: dict[str, Any] = {}
    warnings: list[str] = []

    for unique_id, node in sorted(nodes.items()):
        if node.get("resource_type") != "model":
            continue
        name = str(node.get("name") or "")
        schema = str(node.get("schema") or "")
        identifier = str(node.get("alias") or node.get("identifier") or name)
        if not all(IDENTIFIER_RE.fullmatch(item) for item in (name, schema, identifier)):
            warnings.append(f"skipped {unique_id}: non-simple SQL identifier")
            continue
        columns = node.get("columns") or {}
        fields: dict[str, Any] = {}
        for column_name, column_meta in sorted(columns.items()):
            if not IDENTIFIER_RE.fullmatch(column_name):
                warnings.append(f"skipped column {unique_id}.{column_name}: non-simple identifier")
                continue
            data_type = _map_data_type(str(column_meta.get("data_type") or "string"))
            fields[column_name] = {
                "expression": f"{{alias}}.{column_name}",
                "data_type": data_type,
                "columns": [column_name],
                "groupable": True,
                "filterable": True,
                "description": str(column_meta.get("description") or ""),
            }
        if tenant_column and tenant_column not in {column for column in fields}:
            warnings.append(f"model {unique_id} does not declare tenant column {tenant_column}")
        data_products[name] = {
            "table": f"{schema}.{identifier}",
            "alias": "src",
            "tenant_column": tenant_column,
            "description": str(node.get("description") or ""),
            "fields": fields,
        }

    catalog = {
        "version": f"dbt-import:{manifest.get('metadata', {}).get('dbt_version', 'unknown')}",
        "data_products": data_products,
        "metrics": {},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return {
        "catalog": catalog,
        "warnings": warnings,
        "next_step": (
            "Add reviewed metrics with expression, source columns, base-filter columns, and result checks."
        ),
    }


def _map_data_type(value: str) -> str:
    normalized = re.sub(r"\(.*\)", "", value.lower()).strip()
    if any(token in normalized for token in ("timestamp", "datetime")):
        return "timestamp"
    if normalized == "date":
        return "date"
    if "uuid" in normalized:
        return "uuid"
    if any(token in normalized for token in ("bool",)):
        return "boolean"
    if any(token in normalized for token in ("int", "serial")):
        return "integer"
    if any(
        token in normalized for token in ("numeric", "decimal", "float", "double", "real", "money")
    ):
        return "number"
    return "string"
