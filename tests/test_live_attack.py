from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from tests.support import FakeMCP


def build_state(tmp_path: Path, **overrides) -> AppState:
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


class TargetRecorder:
    """Records the outgoing live-attack call without a real target."""

    def __init__(self, status: int = 200, body: dict | None = None):
        self.status = status
        self.body = body or {"count": 50, "leak_surface": "unauthenticated_exfil"}
        self.calls: list[dict] = []


def patch_httpx(monkeypatch, recorder: TargetRecorder) -> None:
    """Replace httpx.AsyncClient only inside the attack code path."""
    import backend.main as main_module

    original = main_module.httpx.AsyncClient

    class FakeResponse:
        def __init__(self, status: int, body: dict):
            self.status_code = status
            self._body = body
            self.text = "blocked by meta-guardian gateway" if status == 403 else ""

        def json(self):
            return self._body

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.base_url = kwargs.get("base_url")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def get(self, path, params=None, headers=None):
            recorder.calls.append(
                {"path": path, "params": params, "headers": dict(headers or {})}
            )
            return FakeResponse(recorder.status, recorder.body)

    class Wrapper:
        def __new__(cls, *args, **kwargs):
            return FakeClient(*args, **kwargs)

    monkeypatch.setattr(main_module.httpx, "AsyncClient", Wrapper)
    return original


def test_attack_sends_a_real_exfil_request_without_probe_header(tmp_path, monkeypatch):
    state = build_state(tmp_path, trust_forwarded_for=True)
    recorder = TargetRecorder(status=200)
    patch_httpx(monkeypatch, recorder)

    with TestClient(create_app(state)) as client:
        body = client.post("/api/attack").json()

    assert body["status"] == 200
    assert body["records_returned"] == 50
    assert body["incident_expected"] is True

    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["path"] == "/api/v1/ops/data"
    assert call["params"] == {"aircraft": "ALL", "limit": 99999}
    # The whole point: no verification marker, this is attacker traffic.
    assert "x-mg-probe" not in {key.lower() for key in call["headers"]}
    assert call["headers"].get("x-forwarded-for") == "203.0.113.66"


def test_attack_omits_xff_when_forwarding_is_not_trusted(tmp_path, monkeypatch):
    state = build_state(tmp_path, trust_forwarded_for=False)
    recorder = TargetRecorder(status=200)
    patch_httpx(monkeypatch, recorder)

    with TestClient(create_app(state)) as client:
        body = client.post("/api/attack").json()

    call = recorder.calls[0]
    assert "x-forwarded-for" not in call["headers"]
    assert body["attacker_ip"] is None
    assert "TRUST_FORWARDED_FOR is off" in body["hint"]


def test_attack_is_rate_limited_to_one_per_cooldown(tmp_path, monkeypatch):
    state = build_state(tmp_path, trust_forwarded_for=True)
    recorder = TargetRecorder(status=200)
    patch_httpx(monkeypatch, recorder)

    with TestClient(create_app(state)) as client:
        first = client.post("/api/attack")
        assert first.status_code == 200

        second = client.post("/api/attack")
        assert second.status_code == 429
        assert second.headers["retry-after"]
        detail = second.json()["detail"]
        assert detail["error"] == "attack rate limited"
        assert 0 < detail["retry_after_seconds"] <= 10

    # The blocked attempt must not have reached the target.
    assert len(recorder.calls) == 1


def test_attack_reports_why_a_403_did_not_produce_an_incident(tmp_path, monkeypatch):
    state = build_state(tmp_path, trust_forwarded_for=True)
    recorder = TargetRecorder(status=403, body={"count": None})
    patch_httpx(monkeypatch, recorder)

    with TestClient(create_app(state)) as client:
        body = client.post("/api/attack").json()

    assert body["status"] == 403
    assert body["blocked_already"] is True
    assert body["incident_expected"] is False
    assert "already blocked" in body["hint"]


def test_attack_reports_an_unreachable_target(tmp_path, monkeypatch):
    import httpx

    import backend.main as main_module

    class BoomClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(main_module.httpx, "AsyncClient", BoomClient)
    state = build_state(tmp_path)

    with TestClient(create_app(state)) as client:
        response = client.post("/api/attack")

    assert response.status_code == 502
    assert "unreachable" in response.json()["detail"]


def test_attack_cooldown_is_configurable(tmp_path, monkeypatch):
    state = build_state(tmp_path, trust_forwarded_for=True, attack_cooldown_seconds=0.15)
    recorder = TargetRecorder(status=200)
    patch_httpx(monkeypatch, recorder)

    import time as _time

    with TestClient(create_app(state)) as client:
        assert client.post("/api/attack").status_code == 200
        assert client.post("/api/attack").status_code == 429
        _time.sleep(0.2)
        assert client.post("/api/attack").status_code == 200


def test_frontend_exposes_the_live_attack_button(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        html = client.get("/").text
        js = client.get("/static/app.js").text
        css = client.get("/static/style.css").text

    assert 'id="attackBtn"' in html
    assert "FIRE LIVE ATTACK" in html
    assert "real HTTP" in html
    assert "/api/attack" in js
    assert ".btn-attack" in css
