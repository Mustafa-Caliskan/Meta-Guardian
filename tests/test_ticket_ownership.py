"""Task 2 — a change ticket may only suppress the alert for its own owner.

Verified gap before this work: policy_engine.evaluate() checked
``ticket is not None and operator_present`` and never compared
``ticket.operator`` with the identity that actually ran the request. Anybody
able to open a ticket could whitelist any privileged action.
"""

import json
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.edge.policy_engine import ChangeTicketStore, PolicyEngine
from backend.models import (
    ActionType,
    ChangeTicket,
    Classification,
    MCPAction,
    OODADecision,
    PolicyMode,
    Severity,
    utc_now,
)
from tests.support import admin_event, covering_ticket, network_event, usb_event, vision


def decision(confidence: float = 0.93) -> OODADecision:
    return OODADecision(
        incident_id="inc_ticket",
        classification=Classification.THREAT_CRITICAL,
        severity=Severity.CRITICAL,
        confidence=confidence,
        actions=[MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66")],
    )


def engine_with(ticket: ChangeTicket | None) -> PolicyEngine:
    return PolicyEngine(ChangeTicketStore(tickets=[ticket] if ticket else []))


# ------------------------------------------------------- ownership matching --

def test_matching_ticket_and_admin_role_suppresses_the_alert():
    engine = engine_with(covering_ticket(operator="ops-admin"))
    outcome = engine.evaluate(
        events=[admin_event(session_owner="ops-admin", session_role="admin")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is Classification.BENIGN_AUTHORIZED
    assert outcome.mode is PolicyMode.MONITOR
    assert outcome.ticket_owner_match is True
    assert outcome.approved_actions == []


def test_ticket_owned_by_someone_else_does_not_suppress():
    """The actual privilege-escalation path: open a ticket, run someone else's job."""
    engine = engine_with(covering_ticket(operator="ops-engineer"))
    outcome = engine.evaluate(
        events=[admin_event(session_owner="ops-admin", session_role="admin")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.mode is PolicyMode.AUTO
    assert outcome.ticket_owner_match is False
    assert "belongs to ops-engineer" in outcome.reason
    assert "event ran as ops-admin" in outcome.reason


def test_ticket_owner_matched_but_role_is_not_admin():
    engine = engine_with(covering_ticket(operator="ops-engineer"))
    outcome = engine.evaluate(
        events=[admin_event(session_owner="ops-engineer", session_role="operator")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.ticket_owner_match is False
    assert "not 'admin'" in outcome.reason


def test_ticket_without_a_session_identity_does_not_suppress():
    """An event that carries no session owner cannot authorise anything."""
    engine = engine_with(covering_ticket(operator="ops-admin"))
    event = usb_event()  # USB events have no session identity at all
    outcome = engine.evaluate(
        events=[event, network_event(session_owner="", session_role="")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.ticket_owner_match is False
    assert "no session owner" in outcome.reason


def test_expired_ticket_does_not_suppress():
    now = utc_now()
    expired = ChangeTicket(
        ticket_id="CHG-OLD",
        operator="ops-admin",
        reason="past window",
        window_start=now - timedelta(hours=5),
        window_end=now - timedelta(hours=4),
        usb_allowed=True,
    )
    engine = engine_with(expired)
    outcome = engine.evaluate(
        events=[admin_event()],
        proposed=decision(),
        vision=vision(True),
        now=now,
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.ticket_owner_match is None  # no covering ticket at all


def test_no_ticket_leaves_the_match_field_unset():
    engine = engine_with(None)
    outcome = engine.evaluate(
        events=[admin_event()],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )
    assert outcome.ticket_id is None
    assert outcome.ticket_owner_match is None


# --------------------------------------------------------- audit enrichment --

def test_audit_log_records_session_identity(tmp_path: Path):
    from backend import target_service
    from backend.target_service import STATE, app

    STATE.reset(tmp_path / "requests.jsonl")
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/admin/command",
            json={"command": "dump core-db"},
            headers={"x-session-token": "session-7f3a9c"},
        )
        assert response.status_code == 200

    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["session_owner"] == "ops-admin"
    assert entry["session_role"] == "admin"
    assert entry["session_origin_ip"] == "10.0.0.31"
    STATE.reset()


def test_audit_log_records_null_identity_for_anonymous_requests(tmp_path: Path):
    from backend.target_service import STATE, app

    STATE.reset(tmp_path / "requests.jsonl")
    with TestClient(app) as client:
        client.get("/api/v1/ops/data", params={"aircraft": "ALL", "limit": 5})

    entry = json.loads(STATE.log_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["session_owner"] is None
    assert entry["session_role"] is None
    STATE.reset()


# ------------------------------------------------------------- case file ----

def test_casefile_reports_the_ticket_ownership_verdict(tmp_path: Path):
    from backend.casefile import build_casefile
    from backend.models import Incident

    engine = engine_with(covering_ticket(operator="ops-engineer"))
    events = [admin_event(session_owner="ops-admin", session_role="admin")]
    outcome = engine.evaluate(events=events, proposed=decision(), vision=vision(True))

    incident = Incident(id="inc_ticket", scenario="A", events=events, policy=outcome)
    document = build_casefile(incident)

    assert document["policy"]["ticket_owner_match"] is False


# -------------------------------------------------------- demo consistency ----

def test_scenario_c_demo_ticket_matches_the_simulated_session_owner(tmp_path: Path):
    """The demo's own ticket must pass the ownership check it introduced.

    Before the check existed, scenario C's ticket named a different operator than
    the simulated session and still suppressed the alert.
    """
    from backend.config import LLMMode, Settings
    from backend.main import AppState
    from tests.support import FakeMCP

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

    import asyncio

    incident = asyncio.run(state.simulate("C"))

    assert incident.decision.classification is Classification.BENIGN_AUTHORIZED
    assert incident.policy.ticket_owner_match is True
    assert incident.status.value == "dismissed"
