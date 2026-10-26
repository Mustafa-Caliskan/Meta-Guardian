from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import target_service
from backend.models import WAFRule
from backend.target_service import STATE, app


@pytest.fixture()
def client(tmp_path: Path):
    STATE.reset(tmp_path / "target_requests.jsonl")
    with TestClient(app) as test_client:
        yield test_client
    STATE.reset()


def _exfil(client: TestClient, headers: dict[str, str] | None = None):
    return client.get(
        "/api/v1/ops/data",
        params={"aircraft": "ALL", "limit": 99999},
        headers=headers or {},
    )


def test_data_endpoint_starts_vulnerable(client: TestClient):
    response = _exfil(client)
    assert response.status_code == 200
    assert response.json()["leak_surface"] == "unauthenticated_exfil"


def test_request_is_logged_with_flags(client: TestClient):
    _exfil(client)
    log = STATE.log_path.read_text(encoding="utf-8")
    entry = __import__("json").loads(log.strip().splitlines()[-1])
    assert entry["path"] == "/api/v1/ops/data"
    assert "missing_session" in entry["flags"]
    assert any(flag.startswith("exfil_marker:") for flag in entry["flags"])


def test_patch_blocks_exfil_and_verifies_200_to_403(client: TestClient):
    before = _exfil(client)
    assert before.status_code == 200

    rule = WAFRule(
        rule_id="MG-WAF-001",
        blocked_markers=["aircraft=all", "limit=99999"],
        require_session=True,
        rationale="block mass exfiltration",
    )
    applied = client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})
    assert applied.status_code == 200
    assert applied.json()["revision"] == 1

    after = _exfil(client)
    assert after.status_code == 403
    assert after.json()["blocked"] is True


def test_patch_allows_legitimate_session_and_bounded_query(client: TestClient):
    rule = WAFRule(rule_id="MG-WAF-002", blocked_markers=["aircraft=all"], require_session=True)
    client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})

    response = client.get(
        "/api/v1/ops/data",
        params={"aircraft": "PC-1180", "limit": 5},
        headers={"x-session-token": "session-ops-valid"},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 5


def test_revoked_session_is_rejected(client: TestClient):
    revoked = client.post(
        "/internal/gateway/revoke_session", json={"session": "session-7f3a9c"}
    )
    assert revoked.status_code == 200

    response = client.post(
        "/api/v1/admin/command",
        json={"command": "dump core-db"},
        headers={"x-session-token": "session-7f3a9c"},
    )
    assert response.status_code == 401


def test_blocked_ip_gets_403(client: TestClient):
    client.post("/internal/gateway/block_ip", json={"ip": "testclient"})
    response = client.get("/api/v1/ops/flights")
    assert response.status_code == 403
    assert "blocked" in response.text


def test_rollback_restores_vulnerable_state(client: TestClient):
    rule = WAFRule(rule_id="MG-WAF-003", blocked_markers=["aircraft=all"], require_session=True)
    client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})
    assert _exfil(client).status_code == 403

    rolled = client.post("/internal/gateway/rollback")
    assert rolled.json()["rolled_back"] is True
    assert _exfil(client).status_code == 200


def test_empty_rule_is_rejected(client: TestClient):
    rule = WAFRule(rule_id="MG-WAF-004", blocked_markers=[], require_session=False)
    response = client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})
    assert response.status_code == 422


def test_internal_requests_supports_since(client: TestClient):
    _exfil(client)
    client.get("/api/v1/ops/flights")
    payload = client.get("/internal/requests", params={"since": 1}).json()
    assert payload["last_seq"] == 2
    assert [entry["seq"] for entry in payload["requests"]] == [2]


def test_rule_fingerprint_is_stable(client: TestClient):
    rule = WAFRule(rule_id="MG-WAF-005", blocked_markers=["a", "b"], require_session=True)
    first = client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})
    client.post("/internal/gateway/rollback")
    second = client.post("/internal/gateway/apply_rule", json={"rule": rule.model_dump()})
    assert first.json()["fingerprint"] == second.json()["fingerprint"]


def test_target_service_module_exposes_app():
    assert target_service.app.title == "Aviation Ops API"
