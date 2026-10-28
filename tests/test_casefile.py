import json
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.casefile import build_casefile, casefile_filename, render_markdown
from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from backend.models import (
    ActionType,
    Citation,
    Classification,
    EventSource,
    EventType,
    ForensicsReport,
    Incident,
    IncidentStatus,
    MCPAction,
    MCPActionResult,
    OODADecision,
    PatchResult,
    PolicyMode,
    PolicyOutcome,
    SecurityEvent,
    Severity,
    VisionEvidence,
    utc_now,
)
from tests.support import FakeMCP


def _incident() -> Incident:
    now = utc_now()
    events = [
        SecurityEvent(
            source=EventSource.USB,
            type=EventType.USB_INSERTED,
            severity=Severity.HIGH,
            summary="Removable media mounted with 1 suspicious file(s)",
            timestamp=now - timedelta(seconds=1),
            payload={"mountpoint": "E:\\", "findings": [{"name": "payload.ps1"}]},
        ),
        SecurityEvent(
            source=EventSource.NETWORK,
            type=EventType.SUSPICIOUS_API_REQUEST,
            severity=Severity.CRITICAL,
            summary="GET /api/v1/ops/data from 203.0.113.66 -> HTTP 200",
            timestamp=now,
            payload={"ip": "203.0.113.66", "session": "session-7f3a9c", "status": 200},
        ),
    ]

    incident = Incident(
        id="inc_casefile_test",
        scenario="A",
        status=IncidentStatus.PATCHED,
        events=events,
        vision=VisionEvidence(
            operator_present=True,
            presence_known=True,
            confidence=0.94,
            roi=[40, 30, 60, 70],
            motion_ratio=0.0223,
            method="baseline_diff->sam-vit_b@modal",
            model="sam-vit_b@modal",
            description="operator-sized motion detected",
            frame_path="/tmp/evidence/inc/frame.png",
            mask_path="/tmp/evidence/inc/mask.png",
            frame_source="webcam",
        ),
        decision=OODADecision(
            incident_id="inc_casefile_test",
            classification=Classification.THREAT_CRITICAL,
            severity=Severity.CRITICAL,
            confidence=0.93,
            reasoning="USB plus exfiltration",
            evidence_summary="correlated",
            actions=[MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66")],
            model="muse-spark-open-1026@baseten",
            latency_ms=3512.0,
            created_at=now + timedelta(milliseconds=350),
        ),
        policy=PolicyOutcome(
            classification=Classification.THREAT_CRITICAL,
            severity=Severity.CRITICAL,
            confidence=0.93,
            mode=PolicyMode.AUTO,
            reason="confidence 0.93 >= 0.85: auto containment",
            operator_present=True,
            approved_actions=[MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66")],
        ),
        action_results=[
            MCPActionResult(
                action=ActionType.BLOCK_IP_ON_GATEWAY,
                target="203.0.113.66",
                success=True,
                detail="gateway block_list updated",
                executed_at=now + timedelta(milliseconds=460),
            )
        ],
        forensics=ForensicsReport(
            incident_id="inc_casefile_test",
            summary="Reconnaissance preceded the exfiltration.",
            earliest_discovery=now - timedelta(days=3),
            vulnerable_file="backend/target_service.py",
            vulnerable_line=318,
            citations=[
                Citation(
                    log_file="data/history_logs/siem_30d.log",
                    line=11512,
                    excerpt="src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200",
                )
            ],
            citations_verified=True,
            recon_verified=True,
            archive_lines_scanned=12773,
            input_tokens=1026768,
            model="muse-spark-open-1026",
            latency_ms=3256.0,
        ),
        patch=PatchResult(
            incident_id="inc_casefile_test",
            target_file="backend/target_service.py",
            rule_id="MG-WAF-CASE",
            rule_fingerprint="abcdef0123456789",
            applied=True,
            before_status=200,
            after_status=403,
            verified=True,
            verification_note="HTTP 200 -> HTTP 403: PATCH VERIFIED",
            latency_ms=1697.7,
        ),
    )
    return incident


def test_casefile_has_all_required_sections():
    document = build_casefile(_incident())

    assert document["schema_version"]
    for key in (
        "incident",
        "timings",
        "events",
        "vision",
        "decision",
        "policy",
        "mcp_actions",
        "forensics",
        "patch",
    ):
        assert key in document, key


def test_casefile_reports_real_timestamps_and_timings():
    document = build_casefile(_incident())

    assert len(document["events"]) == 2
    timestamps = [event["timestamp"] for event in document["events"]]
    assert all(isinstance(value, str) and value for value in timestamps)
    # MTTD runs from the FIRST correlated event (1 s before "now") to the
    # decision 350 ms after "now", so 1350 ms is the honest figure.
    assert 1349 <= document["timings"]["mttd_ms"] <= 1351
    # first action was 110 ms after the decision
    assert 109 <= document["timings"]["mttr_ms"] <= 111
    assert document["timings"]["patch_latency_ms"] == 1697.7


def test_casefile_vision_fields_are_explicit():
    vision = build_casefile(_incident())["vision"]

    assert vision["presence_known"] is True
    assert vision["operator_present"] is True
    assert vision["mask_file"] == "mask.png"
    assert vision["frame_file"] == "frame.png"
    assert vision["model"] == "sam-vit_b@modal"
    assert vision["roi"] == [40, 30, 60, 70]


def test_casefile_forensics_and_patch_are_verifiable():
    document = build_casefile(_incident())

    assert document["forensics"]["citations_verified"] is True
    assert document["forensics"]["recon_verified"] is True
    assert document["forensics"]["citations"][0]["line"] == 11512

    patch = document["patch"]
    assert patch["before_status"] == 200
    assert patch["after_status"] == 403
    assert patch["verified"] is True
    assert patch["rule_fingerprint"] == "abcdef0123456789"
    assert patch["rolled_back"] is False


def test_casefile_missing_parts_are_null_not_invented():
    bare = Incident(id="inc_bare", scenario="unknown")
    document = build_casefile(bare)

    assert document["vision"] is None
    assert document["decision"] is None
    assert document["policy"] is None
    assert document["forensics"] is None
    assert document["patch"] is None
    assert document["mcp_actions"] == []
    assert document["timings"]["mttd_ms"] is None


def test_markdown_is_a_readable_soc_report():
    markdown = render_markdown(build_casefile(_incident()))

    for heading in (
        "# SOC Case File",
        "## Summary",
        "## Correlated events",
        "## Physical evidence",
        "## OODA decision",
        "## Policy gate",
        "## Containment actions",
        "## Cloud forensics",
        "## Self-healing patch",
    ):
        assert heading in markdown, heading

    assert "MTTD" in markdown
    assert "203.0.113.66" in markdown
    assert "200 → 403" in markdown
    assert "abcdef0123456789" in markdown
    assert "sam-vit_b@modal" in markdown
    assert "| Log file | Line | Excerpt |" in markdown


def test_markdown_escapes_pipes_in_values():
    incident = _incident()
    incident.events[0].summary = "pipe | inside | summary"
    markdown = render_markdown(build_casefile(incident))
    assert "pipe \\| inside \\| summary" in markdown


def test_casefile_filename_uses_the_right_suffix():
    incident = _incident()
    assert casefile_filename(incident, "json").endswith(".json")
    assert casefile_filename(incident, "markdown").endswith(".md")


# --------------------------------------------------------------------- endpoint


def build_state(tmp_path: Path) -> AppState:
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
        persist_incidents=False,
        segmentation_async=False,
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


@pytest.fixture()
def client(tmp_path: Path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as test_client:
        yield test_client, state


def test_casefile_endpoint_returns_markdown_attachment(client):
    test_client, state = client
    incident = test_client.post("/api/simulate", json={"scenario": "A"}).json()

    response = test_client.get(
        f"/api/incidents/{incident['id']}/casefile?format=markdown"
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.startswith("# SOC Case File")
    assert incident["id"] in response.text


def test_casefile_endpoint_returns_json_document(client):
    test_client, state = client
    incident = test_client.post("/api/simulate", json={"scenario": "A"}).json()

    response = test_client.get(
        f"/api/incidents/{incident['id']}/casefile?format=json"
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["incident"]["id"] == incident["id"]
    assert body["events"]
    assert body["mcp_actions"]
    assert body["patch"] is None  # patch was not run


def test_casefile_defaults_to_markdown(client):
    test_client, _ = client
    incident = test_client.post("/api/simulate", json={"scenario": "B"}).json()
    response = test_client.get(f"/api/incidents/{incident['id']}/casefile")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")


def test_casefile_rejects_unknown_format(client):
    test_client, _ = client
    incident = test_client.post("/api/simulate", json={"scenario": "A"}).json()
    response = test_client.get(
        f"/api/incidents/{incident['id']}/casefile?format=pdf"
    )
    assert response.status_code == 422


def test_casefile_missing_incident_is_404(client):
    test_client, _ = client
    assert test_client.get("/api/incidents/inc_missing/casefile").status_code == 404


def test_casefile_reflects_patch_after_it_runs(tmp_path: Path):
    state = build_state(tmp_path)
    import httpx

    from backend.cloud.patcher import Patcher

    applied = {"state": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/internal/gateway/apply_rule":
            applied["state"] = True
            return httpx.Response(200, json={"applied": True, "revision": 1})
        if path == "/internal/gateway/rollback":
            applied["state"] = False
            return httpx.Response(200, json={"rolled_back": True})
        if path == "/api/v1/ops/data":
            return httpx.Response(403 if applied["state"] else 200, json={"ok": True})
        return httpx.Response(404)

    state.patcher = Patcher(
        target_base_url="http://gateway.test",
        transport=httpx.MockTransport(handler),
    )

    with TestClient(create_app(state)) as test_client:
        incident = test_client.post("/api/simulate", json={"scenario": "A"}).json()
        test_client.post(f"/api/incidents/{incident['id']}/patch")

        body = test_client.get(
            f"/api/incidents/{incident['id']}/casefile?format=json"
        ).json()

        assert body["patch"]["verified"] is True
        assert body["patch"]["before_status"] == 200
        assert body["patch"]["after_status"] == 403
        assert body["patch"]["rule_fingerprint"]

        markdown = test_client.get(
            f"/api/incidents/{incident['id']}/casefile?format=markdown"
        ).text
        assert "200 → 403" in markdown
        assert "PATCH VERIFIED" in markdown
