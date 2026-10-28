import json
import time
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from backend.models import IncidentStatus
from tests.support import FakeMCP


def build_state(tmp_path: Path, **setting_overrides) -> AppState:
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
        persist_incidents=False,
        **setting_overrides,
    )
    settings.ensure_dirs()
    try:
        from backend.vision import load_frame

        frame = load_frame(settings.baseline_frame_path)
    except Exception:  # noqa: BLE001 - fall back to a blank frame
        frame = np.zeros((120, 160, 3), dtype=np.uint8)
    return AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )


def wait_for_incidents(state: AppState, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if state.incidents and not state._pipeline_tasks:
            return
        time.sleep(0.05)


def test_net_watcher_ignores_old_log_lines_on_startup(tmp_path):
    from backend.edge.usb_net_watcher import EventBus, NetWatcher

    log = tmp_path / "requests.jsonl"
    log.write_text(
        json.dumps(
            {
                "seq": 1,
                "ip": "203.0.113.66",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL",
                "status": 200,
                "flags": ["exfil_marker:aircraft=all"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    watcher = NetWatcher(EventBus(), log)  # ignore_history=True by default
    assert watcher.poll_once() == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "seq": 2,
                    "ip": "198.51.100.7",
                    "method": "GET",
                    "path": "/api/v1/ops/data",
                    "query": "aircraft=ALL",
                    "status": 200,
                    "flags": ["exfil_marker:aircraft=all"],
                }
            )
            + "\n"
        )
    events = watcher.poll_once()
    assert len(events) == 1
    assert events[0].payload["ip"] == "198.51.100.7"


def test_real_events_flow_from_bus_to_ooda_without_simulate(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        assert client.get("/api/incidents").json()["incidents"] == []

        import asyncio

        async def publish():
            await state.publish(
                __import__("tests.support", fromlist=["usb_event"]).usb_event(
                    str(tmp_path / "usb")
                )
            )
            await state.publish(
                __import__("tests.support", fromlist=["network_event"]).network_event()
            )

        # TestClient runs the app loop in a portal thread; drive the coroutine there.
        client.portal.call(publish)
        wait_for_incidents(state)

        incidents = client.get("/api/incidents").json()["incidents"]
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident["scenario"] == "A"
        assert incident["decision"]["classification"] == "THREAT_CRITICAL"
        assert incident["vision"]["method"].startswith("baseline_diff")
        assert state.real_incidents == 1
        assert state.mcp.calls  # real containment path executed


def test_simulated_events_do_not_double_trigger_the_correlator(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        client.post("/api/simulate", json={"scenario": "A"})
        time.sleep(0.3)
        assert len(state.incidents) == 1
        assert state.real_incidents == 0
        assert client.get("/api/state").json()["counts"]["real_incidents"] == 0


def test_admin_command_from_bus_is_a_ghost_attack(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        import asyncio

        async def publish():
            await state.publish(
                __import__("tests.support", fromlist=["admin_event"]).admin_event()
            )

        client.portal.call(publish)
        wait_for_incidents(state)

        incidents = client.get("/api/incidents").json()["incidents"]
        assert len(incidents) == 1
        assert incidents[0]["scenario"] == "B"
        assert incidents[0]["decision"]["classification"] == "GHOST_ATTACK"


def test_forensics_endpoint_produces_a_verifiable_report(tmp_path):
    from datetime import datetime, timezone

    from backend.cloud.forensics import ArchiveReader, ForensicsEngine
    from scripts.generate_data import MANIFEST_FILENAME, build_archive

    logs = tmp_path / "logs"
    _, manifest = build_archive(
        days=6,
        seed=7,
        end=datetime(2026, 10, 26, 12, tzinfo=timezone.utc),
        out_dir=logs,
    )
    state = build_state(tmp_path)
    state.forensics = ForensicsEngine(
        state.agent.llm,
        reader=ArchiveReader(logs / "siem_30d.log"),
        manifest_path=logs / MANIFEST_FILENAME,
        project_root=logs,
    )

    with TestClient(create_app(state)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        response = client.post(f"/api/incidents/{incident['id']}/forensics")

        assert response.status_code == 200, response.text
        body = response.json()
        report = body["forensics"]
        assert report is not None
        assert report["citations"], report
        assert report["citations_verified"] is True
        assert report["archive_lines_scanned"] > 0


def test_forensics_on_missing_incident_is_404(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        assert client.post("/api/incidents/inc_missing/forensics").status_code == 404


def test_patch_endpoint_marks_incident_patched(tmp_path, monkeypatch):
    import httpx

    from backend.cloud.patcher import Patcher

    state = build_state(tmp_path)
    patched = {"applied": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/internal/gateway/apply_rule":
            patched["applied"] = True
            return httpx.Response(200, json={"applied": True, "revision": 1})
        if path == "/internal/gateway/rollback":
            patched["applied"] = False
            return httpx.Response(200, json={"rolled_back": True})
        if path == "/api/v1/ops/data":
            return httpx.Response(403 if patched["applied"] else 200, json={"ok": True})
        return httpx.Response(404)

    state.patcher = Patcher(
        target_base_url="http://gateway.test",
        transport=httpx.MockTransport(handler),
    )

    with TestClient(create_app(state)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        response = client.post(f"/api/incidents/{incident['id']}/patch")
        assert response.status_code == 200, response.text
        body = response.json()

        assert body["status"] == IncidentStatus.PATCHED.value
        assert body["patch"]["verified"] is True
        assert body["patch"]["before_status"] == 200
        assert body["patch"]["after_status"] == 403
        assert body["patch"]["rule_id"].startswith("MG-WAF-")


def test_patch_on_missing_incident_is_404(tmp_path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        assert client.post("/api/incidents/inc_missing/patch").status_code == 404


def test_incidents_are_persisted_and_reloaded(tmp_path):
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
        persist_incidents=True,
    )
    settings.ensure_dirs()
    from backend.vision import load_frame

    frame = load_frame(settings.baseline_frame_path)
    first = AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )
    with TestClient(create_app(first)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()

    second = AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )
    with TestClient(create_app(second)) as client:
        incidents = client.get("/api/incidents").json()["incidents"]
        assert len(incidents) == 1
        assert incidents[0]["id"] == incident["id"]


def test_segmentation_is_scheduled_off_the_response_path(tmp_path, monkeypatch):
    """A 20 s CPU segmentation must not freeze /api/simulate or the next bundle."""
    import asyncio
    import time as _time

    state = build_state(tmp_path)
    calls: list[str] = []

    async def slow_enrich(incident):
        calls.append(incident.id)
        await asyncio.sleep(0.4)

    monkeypatch.setattr(state, "enrich_segmentation", slow_enrich)

    with TestClient(create_app(state)) as client:
        started = _time.perf_counter()
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        elapsed = _time.perf_counter() - started

        assert incident["id"]
        # The HTTP response must not wait for the 0.4 s "slow" segmentation.
        assert elapsed < 0.4
