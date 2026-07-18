from __future__ import annotations

import pytest

from queryattest.server import mcp


@pytest.mark.asyncio
async def test_all_mcp_tools_publish_structured_output_schemas() -> None:
    tools = await mcp.list_tools()
    names = {tool.name for tool in tools}
    assert names == {
        "list_metrics",
        "describe_metric",
        "prepare_query",
        "preflight_query",
        "execute_approved_query",
        "get_audit_evidence",
    }
    assert all(tool.outputSchema for tool in tools)

    execute_tool = next(tool for tool in tools if tool.name == "execute_approved_query")
    assert execute_tool.outputSchema["title"] == "QueryReceipt"
    assert "receipt_version" in execute_tool.outputSchema["properties"]
    assert "contract_version" not in execute_tool.outputSchema["properties"]
