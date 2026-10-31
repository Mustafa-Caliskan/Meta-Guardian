
"""Task 8 — MITRE ATT&CK mapping.

A security jury expects a technique id next to a finding. The mapping is
deterministic and derived from the evidence, never invented by the model.
"""

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.casefile import build_casefile, render_markdown
from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from backend.models import (
    ActionType,
    Classification,
    EventSource,
    EventType,
    Incident,
    OODADecision,
    SecurityEvent,
    Severity,
    attack_technique_labels,
    attack_techniques,
)
from tests.support import FakeMCP, admin_event, network_event, usb_event


def _incident(classification: Classification, events=None) -> Incident:
    return Incident(
        id="inc_attack",
        scenario="A",
        events=events or [],
        decision=OODADecision(
            incident_id="inc_attack",
            classification=classification,
            severity=Severity.CRITICAL,
        ),
    )


def test_every_classification_returns_at_least_one_technique():
    for classification in Classification:
        techniques = attack_techniques(classification, [], [])
        assert techniques, f"{classification} produced no technique"


def test_expected_mapping_per_classification():
    assert attack_techniques(Classification.GHOST_ATTACK, [], []) == ["T1078"]
    assert attack_techniques(Classification.CREDENTIAL_MISUSE, [], []) == ["T1078"]
    assert attack_techniques(Classification.THREAT_CRITICAL, [], []) == ["T1200"]


def test_usb_event_maps_to_hardware_additions():
    assert "T1200" in attack_techniques(Classification.THREAT_CRITICAL, [usb_event()])


def test_exfiltration_event_maps_to_t1567():
    techniques = attack_techniques(
        Classification.THREAT_CRITICAL, [network_event()]
    )
    assert "T1567" in techniques


def test_kill_process_action_maps_to_service_stop():
    techniques = attack_techniques(
        Classification.THREAT_CRITICAL, [], [ActionType.KILL_PROCESS]
    )
    assert "T1489" in techniques


def test_unauthorized_process_event_maps_to_service_stop():
    event = SecurityEvent(
        source=EventSource.PROCESS,
        type=EventType.UNAUTHORIZED_PROCESS,
        summary="spawned by payload",
    )
    assert "T1489" in attack_techniques(Classification.THREAT_CRITICAL, [event])


def test_labels_resolve_known_names():
    labels = attack_technique_labels(["T1078", "T1200", "T1567", "T1489", "T9999"])
    assert labels[0] == {"id": "T1078", "name": "Valid Accounts"}
    assert labels[-1] == {"id": "T9999", "name": "unknown"}


def test_incident_exposes_the_mapping_in_its_json():
    incident = _incident(Classification.GHOST_ATTACK, [admin_event()])
    dumped = incident.model_dump(mode="json")
    assert any(item["id"] == "T1078" for item in dumped["attack_techniques"])


def test_casefile_and_markdown_show_the_technique():
    document = build_casefile(_incident(Classification.THREAT_CRITICAL, [usb_event()]))
    assert document["attack_techniques"]
    markdown = render_markdown(document)
    assert "## MITRE ATT&CK" in markdown
    assert "T1200" in markdown
    assert "Hardware Additions" in markdown


def test_cockpit_api_includes_the_technique_badge_data(tmp_path: Path):
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
    state = AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )
    with TestClient(create_app(state)) as client:
        client.post("/api/simulate", json={"scenario": "A"})
        incidents = client.get("/api/incidents").json()["incidents"]
        assert incidents[0]["attack_techniques"]
        ids = {item["id"] for item in incidents[0]["attack_techniques"]}
        assert {"T1200", "T1567"} <= ids
