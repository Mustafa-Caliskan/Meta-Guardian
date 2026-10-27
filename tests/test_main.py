import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from backend.models import PolicyMode
from tests.support import FakeMCP, StubLLM


def build_state(tmp_path, mcp=None, **kwargs):
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
    )
    settings.ensure_dirs()
    frame = np.zeros((120, 160, 3), dtype=np.uint8)

    state = AppState(
        settings=settings,
        mcp=mcp if mcp is not None else FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
        **kwargs,
    )
    return state


@pytest.fixture()
def state(tmp_path):
    return build_state(tmp_path)


@pytest.fixture()
def client(state):
    with TestClient(create_app(state)) as test_client:
        yield test_client


def test_health_and_config(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["mode"] == "mock"

    config = client.get("/api/config").json()
    assert config["models"]["sam"] == "sam-3.1"
    assert config["confidence_bands"] == {"auto": 0.85, "approval": 0.5}
    assert config["rate_limit"]["max_actions_per_minute"] == 30


def test_scenario_catalog(client):
    scenarios = client.get("/api/scenarios").json()["scenarios"]
    assert [item["id"] for item in scenarios] == ["A", "B", "C"]


def test_index_and_static_are_served(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "META" in index.text
    assert "streamlit" not in index.text.lower()

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "new WebSocket" in script.text

    css = client.get("/static/style.css")
    assert css.status_code == 200
    assert "--cyan" in css.text


def test_scenario_a_contains_threat_and_serves_evidence(client, state):
    response = client.post("/api/simulate", json={"scenario": "A"})
    assert response.status_code == 200, response.text

    incident = response.json()
    assert incident["scenario"] == "A"
    assert incident["status"] == "contained"
    assert incident["decision"]["classification"] == "THREAT_CRITICAL"
    assert incident["policy"]["mode"] == "auto"
    assert len(incident["action_results"]) == 3

    calls = {name: args for name, args in state.mcp.calls}
    assert calls["block_ip_on_gateway"] == {"ip": "203.0.113.66"}
    assert calls["revoke_session_token"] == {"session": "session-7f3a9c"}
    assert calls["quarantine_usb_file"]["filename"] == "payload.ps1"

    incident_id = incident["id"]
    frame = client.get(f"/api/incidents/{incident_id}/frame")
    assert frame.status_code == 200
    assert frame.headers["content-type"] == "image/png"

    mask = client.get(f"/api/incidents/{incident_id}/mask")
    assert mask.status_code == 200

    listed = client.get("/api/incidents").json()["incidents"]
    assert listed[0]["id"] == incident_id

    events = client.get("/api/events").json()["events"]
    assert any(event["source"] == "usb" for event in events)
    assert any(event["source"] == "network" for event in events)


def test_scenario_b_is_ghost_attack(client, state):
    incident = client.post("/api/simulate", json={"scenario": "B"}).json()

    assert incident["scenario"] == "B"
    assert incident["decision"]["classification"] == "GHOST_ATTACK"
    assert incident["vision"]["operator_present"] is False
    assert incident["status"] == "contained"
    executed = {name for name, _ in state.mcp.calls}
    assert executed == {"block_ip_on_gateway", "revoke_session_token"}


def test_scenario_c_is_benign_and_has_no_side_effects(client, state):
    incident = client.post("/api/simulate", json={"scenario": "C"}).json()

    assert incident["scenario"] == "C"
    assert incident["decision"]["classification"] == "BENIGN_AUTHORIZED"
    assert incident["policy"]["mode"] == "monitor"
    assert incident["status"] == "dismissed"
    assert state.mcp.calls == []
    assert state.tickets.tickets == []  # temporary ticket cleaned up


def test_temporary_ticket_is_removed_after_scenario_c(client, state):
    client.post("/api/simulate", json={"scenario": "C"})
    assert state.tickets.tickets == []


def test_approval_flow_executes_pending_actions(tmp_path):
    mcp = FakeMCP()
    state = build_state(tmp_path, mcp=mcp)
    state.agent.llm = StubLLM(
        {
            "classification": "THREAT_CRITICAL",
            "severity": "high",
            "confidence": 0.62,
            "reasoning": "suspicious but not conclusive",
            "evidence_summary": "usb plus network",
            "actions": [
                {"action": "block_ip_on_gateway", "target": "203.0.113.66"},
                {"action": "revoke_session_token", "target": "session-7f3a9c"},
            ],
        }
    )

    with TestClient(create_app(state)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        assert incident["policy"]["mode"] == "approval"
        assert incident["status"] == "open"
        assert len(incident["policy"]["pending_actions"]) == 2
        assert mcp.calls == []

        approved = client.post(f"/api/incidents/{incident['id']}/approve")
        assert approved.status_code == 200
        body = approved.json()
        assert body["status"] == "contained"
        assert body["policy"]["pending_actions"] == []
        assert len(body["action_results"]) == 2
        assert len(mcp.calls) == 2


def test_approve_rejects_non_pending_incident(client):
    incident = client.post("/api/simulate", json={"scenario": "A"}).json()
    response = client.post(f"/api/incidents/{incident['id']}/approve")
    assert response.status_code == 409


def test_dismiss_and_missing_incident(client, tmp_path):
    mcp = FakeMCP(success=False)
    state = build_state(tmp_path / "fail", mcp=mcp)
    with TestClient(create_app(state)) as failing:
        incident = failing.post("/api/simulate", json={"scenario": "A"}).json()
        assert incident["status"] == "open"

        dismissed = failing.post(f"/api/incidents/{incident['id']}/dismiss")
        assert dismissed.json()["status"] == "dismissed"

        assert failing.get("/api/incidents/inc_missing").status_code == 404
        assert failing.post("/api/incidents/inc_missing/dismiss").status_code == 404
        assert failing.get("/api/incidents/inc_missing/frame").status_code == 404


def test_invalid_scenario_is_rejected(client):
    assert client.post("/api/simulate", json={"scenario": "D"}).status_code == 422


def test_gateway_reports_degraded_when_target_is_down(client):
    body = client.get("/api/gateway").json()
    assert body["reachable"] is False
    assert "blocked_ips" in body


def test_state_snapshot_counts(client):
    client.post("/api/simulate", json={"scenario": "A"})
    snapshot = client.get("/api/state").json()
    assert snapshot["counts"]["incidents"] == 1
    assert snapshot["counts"]["contained"] == 1
    assert snapshot["models"]["sam"] == "sam-3.1"
    assert snapshot["latest_incident"]["scenario"] == "A"


def test_websocket_hello_and_ping(client):
    with client.websocket_connect("/ws") as websocket:
        hello = websocket.receive_json()
        assert hello["type"] == "hello"
        assert "state" in hello

        websocket.send_text("ping")
        assert websocket.receive_json() == {"type": "pong"}


def test_websocket_receives_live_event(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.receive_json()  # hello

        client.post("/api/simulate", json={"scenario": "A"})

        seen_event = False
        seen_incident = False
        for _ in range(20):
            message = websocket.receive_json()
            if message["type"] == "event":
                seen_event = True
            if message["type"] == "incident":
                seen_incident = True
            if seen_event and seen_incident:
                break

        assert seen_event is True
        assert seen_incident is True


def test_streamlit_is_not_a_dependency():
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text(
        encoding="utf-8"
    )
    assert "streamlit" not in text.lower()
