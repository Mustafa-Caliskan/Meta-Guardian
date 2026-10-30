"""Task 1 — control-plane authentication and human accountability.

Verified gap before this work: every /api route was unauthenticated (including
POST /api/attack) and approve() recorded only the literal string
"| approved by human operator" — no identity, no timestamp, no reject path.
"""

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from backend.models import IncidentStatus, PolicyMode
from tests.support import FakeMCP, StubLLM

TOKEN = "test-cockpit-token"


def build_state(tmp_path, **overrides) -> AppState:
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
        persist_incidents=False,
        segmentation_async=False,
        **overrides,
    )
    settings.ensure_dirs()
    frame = np.zeros((120, 160, 3), dtype=np.uint8)
    return AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )


def auth_headers(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def open_client(tmp_path):
    """Auth disabled: the local demo default."""
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        yield client, state


@pytest.fixture()
def locked_client(tmp_path):
    """Auth enabled."""
    state = build_state(
        tmp_path, cockpit_token=TOKEN, cockpit_operator="mustafa"
    )
    with TestClient(create_app(state)) as client:
        yield client, state


# ------------------------------------------------------------------ auth ----

def test_health_stays_open_when_auth_is_enabled(locked_client):
    client, _ = locked_client
    assert client.get("/api/health").status_code == 200


def test_config_stays_open_so_the_browser_can_discover_auth(locked_client):
    client, _ = locked_client
    response = client.get("/api/config")
    assert response.status_code == 200
    assert response.json()["cockpit_auth"] == "enabled"
    # no operator identity leaked without auth
    assert "operator" not in response.json()


def test_protected_routes_reject_missing_token(locked_client):
    client, _ = locked_client
    for method, path in (
        ("get", "/api/state"),
        ("get", "/api/events"),
        ("get", "/api/incidents"),
        ("get", "/api/metrics"),
        ("get", "/api/gateway"),
        ("get", "/api/scenarios"),
        ("get", "/api/whoami"),
        ("post", "/api/attack"),
        ("post", "/api/simulate"),
    ):
        kwargs = {"json": {"scenario": "A"}} if path == "/api/simulate" else {}
        response = getattr(client, method)(path, **kwargs)
        assert response.status_code == 401, (method, path, response.status_code)


def test_protected_routes_reject_a_wrong_token(locked_client):
    client, _ = locked_client
    assert client.get("/api/state", headers=auth_headers("nope")).status_code == 401
    assert client.get(
        "/api/state", headers={"Authorization": "Basic abc"}
    ).status_code == 401


def test_correct_token_is_accepted(locked_client):
    client, _ = locked_client
    response = client.get("/api/state", headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["mode"] == "mock"


def test_whoami_returns_the_configured_operator(locked_client):
    client, _ = locked_client
    body = client.get("/api/whoami", headers=auth_headers()).json()
    assert body == {"operator": "mustafa", "auth": "enabled"}


def test_auth_disabled_keeps_the_demo_open(open_client):
    client, _ = open_client
    assert client.get("/api/state").status_code == 200
    assert client.get("/api/config").json()["cockpit_auth"] == "disabled"
    body = client.get("/api/whoami").json()
    assert body["auth"] == "disabled"
    assert body["operator"]


# --------------------------------------------------------------- WebSocket --

def test_websocket_rejects_missing_token(locked_client):
    client, _ = locked_client
    with pytest.raises(Exception):
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()


def test_websocket_accepts_a_valid_token(locked_client):
    client, _ = locked_client
    with client.websocket_connect(f"/ws?token={TOKEN}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"


def test_websocket_stays_open_when_auth_is_disabled(open_client):
    client, _ = open_client
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "hello"


# ------------------------------------------------------------ accountability --

def _pending_incident(client, headers=None) -> dict:
    """Force the approval band so approve/reject have something to act on."""
    state = client.app.state.mg
    state.agent.llm = StubLLM(
        {
            "classification": "THREAT_CRITICAL",
            "severity": "high",
            "confidence": 0.62,
            "reasoning": "suspicious but not conclusive",
            "actions": [
                {"action": "block_ip_on_gateway", "target": "203.0.113.66"},
            ],
        }
    )
    response = client.post("/api/simulate", json={"scenario": "A"}, headers=headers or {})
    assert response.status_code == 200, response.text
    incident = response.json()
    assert incident["policy"]["mode"] == "approval"
    return incident


def test_approve_records_operator_and_timestamp(open_client):
    client, _ = open_client
    incident = _pending_incident(client)

    body = client.post(f"/api/incidents/{incident['id']}/approve").json()

    assert body["status"] == IncidentStatus.CONTAINED.value
    assert body["policy"]["approved_by"]
    assert body["policy"]["approved_at"]
    assert body["decided_by"] == body["policy"]["approved_by"]
    assert body["decided_at"]
    # the old string hack must be gone
    assert "approved by human operator" not in body["policy"]["reason"]


def test_approve_uses_the_authenticated_operator(locked_client):
    client, _ = locked_client
    incident = _pending_incident(client, auth_headers())

    body = client.post(
        f"/api/incidents/{incident['id']}/approve", headers=auth_headers()
    ).json()

    assert body["policy"]["approved_by"] == "mustafa"
    assert body["decided_by"] == "mustafa"


def test_reject_records_a_human_refusal_and_runs_nothing(locked_client):
    client, _ = locked_client
    state = client.app.state.mg
    incident = _pending_incident(client, auth_headers())
    calls_before = len(state.mcp.calls)

    body = client.post(
        f"/api/incidents/{incident['id']}/reject",
        json={"reason": "false positive, approved maintenance"},
        headers=auth_headers(),
    ).json()

    assert body["status"] == IncidentStatus.DISMISSED.value
    assert body["policy"]["rejected_by"] == "mustafa"
    assert body["policy"]["rejected_at"]
    assert body["policy"]["rejection_reason"] == "false positive, approved maintenance"
    assert body["policy"]["pending_actions"] == []
    assert len(state.mcp.calls) == calls_before  # nothing executed


def test_reject_without_a_pending_approval_is_rejected(open_client):
    client, _ = open_client
    incident = client.post("/api/simulate", json={"scenario": "A"}).json()
    # scenario A lands in AUTO, so there is nothing to reject
    response = client.post(f"/api/incidents/{incident['id']}/reject", json={"reason": "x"})
    assert response.status_code == 409


def test_dismiss_records_operator(open_client):
    client, _ = open_client
    incident = client.post("/api/simulate", json={"scenario": "A"}).json()
    body = client.post(f"/api/incidents/{incident['id']}/dismiss").json()
    assert body["status"] == IncidentStatus.DISMISSED.value
    assert body["decided_by"]
    assert body["decided_at"]


# ----------------------------------------------------------------- casefile --

def test_casefile_contains_the_human_decision(locked_client):
    client, _ = locked_client
    incident = _pending_incident(client, auth_headers())
    client.post(f"/api/incidents/{incident['id']}/approve", headers=auth_headers())

    body = client.get(
        f"/api/incidents/{incident['id']}/casefile?format=json", headers=auth_headers()
    ).json()

    human = body["human_decision"]
    assert human is not None
    assert human["action"] == "approved"
    assert human["operator"] == "mustafa"
    assert human["at"]

    markdown = client.get(
        f"/api/incidents/{incident['id']}/casefile?format=markdown",
        headers=auth_headers(),
    ).text
    assert "## Human decision" in markdown
    assert "mustafa" in markdown


def test_casefile_says_so_when_no_human_was_involved(open_client):
    client, _ = open_client
    incident = client.post("/api/simulate", json={"scenario": "A"}).json()
    body = client.get(f"/api/incidents/{incident['id']}/casefile?format=json").json()
    assert body["human_decision"] is None

    markdown = client.get(
        f"/api/incidents/{incident['id']}/casefile?format=markdown"
    ).text
    assert "No human decision" in markdown


def test_casefile_reports_a_rejection(open_client):
    client, _ = open_client
    incident = _pending_incident(client)
    client.post(
        f"/api/incidents/{incident['id']}/reject", json={"reason": "authorized backup"}
    )
    body = client.get(f"/api/incidents/{incident['id']}/casefile?format=json").json()
    assert body["human_decision"]["action"] == "rejected"
    assert body["human_decision"]["reason"] == "authorized backup"
