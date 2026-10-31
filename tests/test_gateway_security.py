import dataclasses
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import target_service
from backend.edge.mcp_server import MCPServer
from backend.target_service import STATE, app


@pytest.fixture()
def client(tmp_path: Path):
    STATE.reset(tmp_path / "requests.jsonl")
    with TestClient(app) as test_client:
        yield test_client
    STATE.reset()


@pytest.fixture()
def secured(monkeypatch):
    patched = dataclasses.replace(target_service.settings, internal_api_token="s3cret")
    monkeypatch.setattr(target_service, "settings", patched)
    return patched


def test_internal_endpoints_require_a_token_when_configured(client, secured):
    assert client.get("/internal/state").status_code == 401
    assert client.post("/internal/gateway/block_ip", json={"ip": "192.0.2.1"}).status_code == 401
    assert client.post("/internal/reset").status_code == 401

    ok = client.get("/internal/state", headers={"x-internal-token": "s3cret"})
    assert ok.status_code == 200
    wrong = client.get("/internal/state", headers={"x-internal-token": "nope"})
    assert wrong.status_code == 401


def test_public_api_is_not_gated_by_the_internal_token(client, secured):
    assert client.get("/api/v1/ops/flights").status_code == 200


def test_internal_token_defaults_to_open_for_local_dev(client):
    # No token configured in the default environment: the demo still works.
    assert client.get("/internal/state").status_code == 200


def test_forwarded_for_is_ignored_unless_trusted(client):
    response = client.get(
        "/api/v1/ops/data",
        params={"aircraft": "ALL", "limit": 99999},
        headers={"x-forwarded-for": "203.0.113.66"},
    )
    assert response.status_code == 200

    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["ip"] == "testclient"
    assert entry["forwarded_for"] == "203.0.113.66"


def test_forwarded_for_is_used_when_trusted(client, monkeypatch):
    patched = dataclasses.replace(target_service.settings, trust_forwarded_for=True)
    monkeypatch.setattr(target_service, "settings", patched)

    client.get(
        "/api/v1/ops/data",
        params={"aircraft": "ALL", "limit": 99999},
        headers={"x-forwarded-for": "203.0.113.66, 10.0.0.9"},
    )

    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["ip"] == "203.0.113.66"
    assert entry["forwarded_for"].startswith("203.0.113.66")


def test_invalid_forwarded_for_falls_back_to_peer(client, monkeypatch):
    patched = dataclasses.replace(target_service.settings, trust_forwarded_for=True)
    monkeypatch.setattr(target_service, "settings", patched)

    client.get(
        "/api/v1/ops/data",
        params={"aircraft": "ALL", "limit": 5},
        headers={"x-forwarded-for": "not-an-ip"},
    )
    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["ip"] == "testclient"


def test_mcp_sends_the_internal_token(tmp_path):
    import httpx

    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-internal-token"))
        return httpx.Response(200, json={"blocked": True})

    server = MCPServer(
        target_base_url="http://gw",
        quarantine_dir=tmp_path,
        transport=httpx.MockTransport(handler),
        internal_token="s3cret",
    )
    import asyncio

    result = asyncio.run(server.block_ip_on_gateway("192.0.2.5"))
    assert result.success is True
    assert seen == ["s3cret"]


class FakeProcess:
    def __init__(self, pid: int, name: str):
        self.pid = pid
        self._name = name
        self.terminated = False

    def name(self) -> str:
        return self._name

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout=None) -> int:
        return 0


def test_kill_process_allowlist_blocks_unknown_names(tmp_path):
    import asyncio

    created: list[FakeProcess] = []

    def factory(pid: int) -> FakeProcess:
        process = FakeProcess(pid, "notepad.exe")
        created.append(process)
        return process

    server = MCPServer(
        target_base_url="http://gw",
        quarantine_dir=tmp_path,
        process_factory=factory,
        allowed_process_names={"evil.exe"},
    )
    result = asyncio.run(server.kill_process(4242))

    assert result.success is False
    assert "allowlist" in result.detail
    assert created[0].terminated is False


def test_kill_process_allowlist_permits_listed_names(tmp_path):
    import asyncio

    def factory(pid: int) -> FakeProcess:
        return FakeProcess(pid, "evil.exe")

    server = MCPServer(
        target_base_url="http://gw",
        quarantine_dir=tmp_path,
        process_factory=factory,
        allowed_process_names={"evil.exe"},
    )
    result = asyncio.run(server.kill_process(4243))

    assert result.success is True
    assert "evil.exe" in result.detail


def test_external_admin_session_is_accepted_and_tagged_remote(client):
    """The console-collision demo needs an admin session that is not on the LAN.

    ``session-ext-admin`` is the same admin identity established from an external
    address, so with MG_MANAGEMENT_NETWORKS configured the origin still reads as
    remote and the policy engine can classify CREDENTIAL_MISUSE.
    """
    response = client.post(
        "/api/v1/admin/command",
        json={"command": "dump core-db", "target": "ops-core"},
        headers={"x-session-token": "session-ext-admin"},
    )
    assert response.status_code == 200

    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["session_owner"] == "ops-admin"
    assert entry["session_role"] == "admin"
    assert entry["session_origin_ip"] == "203.0.113.66"


def test_admin_command_without_a_session_is_rejected(client):
    response = client.post(
        "/api/v1/admin/command",
        json={"command": "dump core-db", "target": "ops-core"},
    )
    assert response.status_code == 401


def test_trigger_attack_defaults_to_the_external_admin_session():
    from scripts.trigger_attack import DEFAULT_ADMIN_SESSION

    assert DEFAULT_ADMIN_SESSION in STATE.sessions
    assert STATE.sessions[DEFAULT_ADMIN_SESSION]["role"] == "admin"
    assert STATE.sessions[DEFAULT_ADMIN_SESSION]["origin_ip"] == "203.0.113.66"
