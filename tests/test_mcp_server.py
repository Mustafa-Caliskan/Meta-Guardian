import json
import os
import stat
from pathlib import Path

import httpx
import pytest

from backend.edge.mcp_server import MCPServer, MCPToolError
from backend.models import ActionType


def gateway_transport(calls: list, *, status: int = 200, body: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content or b"{}")
        calls.append((request.url.path, payload))
        if status >= 400:
            return httpx.Response(status, text="gateway error")
        return httpx.Response(status, json=body or {"ok": True})

    return httpx.MockTransport(handler)


@pytest.fixture()
def server(tmp_path: Path) -> MCPServer:
    calls: list = []
    return MCPServer(
        target_base_url="http://gateway.test",
        quarantine_dir=tmp_path / "vault",
        transport=gateway_transport(calls),
    )


@pytest.fixture()
def drive(tmp_path: Path) -> Path:
    path = tmp_path / "usb"
    path.mkdir()
    return path


async def test_quarantine_moves_file_and_writes_receipt(server: MCPServer, drive: Path):
    payload = drive / "payload.ps1"
    payload.write_text("Write-Host 'staged'", encoding="utf-8")
    original_size = payload.stat().st_size

    result = await server.call_tool(
        ActionType.QUARANTINE_USB_FILE.value,
        {"drive_path": str(drive), "filename": "payload.ps1"},
    )

    assert result.success is True
    assert not payload.exists()
    quarantined = list((Path(server.quarantine_dir)).glob("*payload.ps1.quarantine"))
    assert len(quarantined) == 1

    receipt = Path(str(quarantined[0]) + ".receipt.json")
    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["sha256"] and len(data["sha256"]) == 64
    assert data["original_path"].endswith("payload.ps1")
    assert data["size"] == original_size
    assert "read-only" in result.detail

    os.chmod(quarantined[0], stat.S_IWRITE)
    os.chmod(receipt, stat.S_IWRITE)


async def test_quarantine_is_idempotent(server: MCPServer, drive: Path):
    (drive / "payload.ps1").write_text("x", encoding="utf-8")
    args = {"drive_path": str(drive), "filename": "payload.ps1"}

    first = await server.call_tool(ActionType.QUARANTINE_USB_FILE.value, args)
    second = await server.call_tool(ActionType.QUARANTINE_USB_FILE.value, args)

    assert first.success and second.success
    assert "already quarantined" in second.detail

    for item in Path(server.quarantine_dir).iterdir():
        os.chmod(item, stat.S_IWRITE)


async def test_quarantine_rejects_path_traversal(server: MCPServer, drive: Path):
    outside = drive.parent / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    result = await server.call_tool(
        ActionType.QUARANTINE_USB_FILE.value,
        {"drive_path": str(drive), "filename": "../outside.txt"},
    )

    assert result.success is False
    assert "traversal" in result.detail
    assert outside.exists()


async def test_quarantine_missing_file_fails(server: MCPServer, drive: Path):
    result = await server.call_tool(
        ActionType.QUARANTINE_USB_FILE.value,
        {"drive_path": str(drive), "filename": "nope.ps1"},
    )
    assert result.success is False
    assert "not found" in result.detail


async def test_block_ip_calls_gateway(server: MCPServer):
    calls: list = []
    server.transport = gateway_transport(calls, body={"blocked": True})

    result = await server.call_tool(
        ActionType.BLOCK_IP_ON_GATEWAY.value, {"ip": "203.0.113.66"}
    )

    assert result.success is True
    assert result.target == "203.0.113.66"
    path, payload = calls[0]
    assert path == "/internal/gateway/block_ip"
    assert payload["ip"] == "203.0.113.66"


async def test_block_ip_refuses_loopback(server: MCPServer):
    result = await server.call_tool(
        ActionType.BLOCK_IP_ON_GATEWAY.value, {"ip": "127.0.0.1"}
    )
    assert result.success is False
    assert "loopback" in result.detail


async def test_block_ip_rejects_invalid_address(server: MCPServer):
    result = await server.call_tool(
        ActionType.BLOCK_IP_ON_GATEWAY.value, {"ip": "not-an-ip"}
    )
    assert result.success is False
    assert "invalid IP" in result.detail


async def test_block_ip_reports_unreachable_gateway(server: MCPServer):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    server.transport = httpx.MockTransport(boom)
    result = await server.call_tool(
        ActionType.BLOCK_IP_ON_GATEWAY.value, {"ip": "198.51.100.7"}
    )
    assert result.success is False
    assert "unreachable" in result.detail


async def test_revoke_session_calls_gateway(server: MCPServer):
    calls: list = []
    server.transport = gateway_transport(calls, body={"revoked": True})

    result = await server.call_tool(
        ActionType.REVOKE_SESSION_TOKEN.value, {"session": "session-7f3a9c"}
    )

    assert result.success is True
    path, payload = calls[0]
    assert path == "/internal/gateway/revoke_session"
    assert payload["session"] == "session-7f3a9c"


async def test_revoke_rejects_empty_token(server: MCPServer):
    result = await server.call_tool(
        ActionType.REVOKE_SESSION_TOKEN.value, {"session": "-"}
    )
    assert result.success is False


class FakeProcess:
    def __init__(self, pid: int):
        self.pid = pid
        self.terminated = False
        self.waited = False

    def name(self) -> str:
        return "evil.exe"

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        return 0


async def test_kill_process_terminates(tmp_path: Path):
    created: list[FakeProcess] = []

    def factory(pid: int) -> FakeProcess:
        process = FakeProcess(pid)
        created.append(process)
        return process

    server = MCPServer(
        target_base_url="http://gateway.test",
        quarantine_dir=tmp_path,
        process_factory=factory,
    )
    result = await server.call_tool(ActionType.KILL_PROCESS.value, {"pid": 4242})

    assert result.success is True
    assert "evil.exe" in result.detail
    assert created[0].terminated and created[0].waited


async def test_kill_process_refuses_protected_pid(tmp_path: Path):
    server = MCPServer(
        target_base_url="http://gateway.test",
        quarantine_dir=tmp_path,
        process_factory=lambda pid: FakeProcess(pid),
    )
    result = await server.call_tool(ActionType.KILL_PROCESS.value, {"pid": os.getpid()})
    assert result.success is False
    assert "protected" in result.detail


async def test_call_tool_requires_arguments(server: MCPServer):
    with pytest.raises(MCPToolError):
        await server.call_tool(ActionType.BLOCK_IP_ON_GATEWAY.value, {})


async def test_call_tool_unknown_tool_raises(server: MCPServer):
    with pytest.raises(MCPToolError):
        await server.call_tool("rm_rf", {})


def test_list_tools_contains_all_four(server: MCPServer):
    names = {tool["name"] for tool in server.list_tools()}
    assert names == {item.value for item in ActionType}


async def test_json_rpc_surface(server: MCPServer):
    init = await server.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["serverInfo"]["name"] == "meta-guardian"

    listed = await server.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(listed["result"]["tools"]) == 4

    calls: list = []
    server.transport = gateway_transport(calls, body={"blocked": True})
    called = await server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "block_ip_on_gateway", "arguments": {"ip": "192.0.2.5"}},
        }
    )
    assert called["result"]["isError"] is False
    assert "192.0.2.5" in called["result"]["content"][0]["text"]

    unknown = await server.handle_rpc(
        {"jsonrpc": "2.0", "id": 4, "method": "nope"}
    )
    assert unknown["error"]["code"] == -32601

    bad_tool = await server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "rm_rf", "arguments": {}},
        }
    )
    assert bad_tool["error"]["code"] == -32602
