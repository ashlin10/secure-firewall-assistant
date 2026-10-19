import asyncio
import json
import os
import sys

import pytest
from mcp import Client, StdioServerParameters

from secure_firewall_assistant.server import build_server


def data(result):
    result = result.model_dump(by_alias=True)
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    return json.loads(next(c["text"] for c in result["content"] if c["type"] == "text"))


def test_tool_discovery_and_mock_device_calls(assistant, lab):
    async def run():
        async with Client(build_server(assistant)) as client:
            tools = await client.list_tools()
            names = {t.name for t in tools.tools}
            assert len(names) == 13
            assert {"execute_configuration", "deploy_configuration", "verify_configuration"} <= names
            annotations = {t.name: t.annotations for t in tools.tools}
            assert annotations["execute_configuration"].read_only_hint is False
            result = data(await client.call_tool("discover_operations", {"query": "networks", "method": "post"}))
            assert result["total"] >= 1
            result = data(await client.call_tool("execute_configuration", {
                "target": "lab-fmc-1", "operation_id": "createMultipleNetworkObject",
                "authorization_request": "Create branch", "body": {"name": "branch", "type": "Network", "value": "192.0.2.0/24"}}))
            assert result["verification"]["status"] == "verified_in_fmc"
            assert result["deployment_performed"] is False
            result = data(await client.call_tool("execute_configuration", {
                "target": "lab-fmc-1", "operation_id": "createDeploymentRequest",
                "authorization_request": "Configure branch", "body": {}}))
            assert result["error"]["code"] == "operation_guard"
    asyncio.run(run())


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_real_stdio_process_is_clean_and_discovers_tools(tmp_path, mode):
    async def run():
        params = StdioServerParameters(command=sys.executable, args=["-m", "secure_firewall_assistant.cli", "serve"],
                                       env={**os.environ, "SFA_DATA_DIR": str(tmp_path / "private")})
        async with Client(params, read_timeout_seconds=20, mode=mode) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 13
            result = data(await client.call_tool("assistant_health"))
            assert result["schema"]["operations"] == 1623
            assert result["network_access_tested"] is False
            devices = data(await client.call_tool("list_devices"))
            assert devices["devices"] == []
    asyncio.run(run())
