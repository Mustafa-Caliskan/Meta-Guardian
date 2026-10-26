from datetime import timedelta

from backend.models import (
    ActionType,
    ChangeTicket,
    Classification,
    EventSource,
    EventType,
    Incident,
    MCPAction,
    OODADecision,
    PatchResult,
    SecurityEvent,
    Severity,
    utc_now,
)


def test_event_gets_id_and_utc_timestamp():
    event = SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        severity=Severity.HIGH,
        summary="USB inserted",
    )
    assert event.id.startswith("evt_")
    assert event.timestamp.tzinfo is not None


def test_change_ticket_window():
    now = utc_now()
    ticket = ChangeTicket(
        ticket_id="CHG-1",
        operator="mustafa",
        reason="maintenance",
        window_start=now - timedelta(minutes=5),
        window_end=now + timedelta(minutes=5),
    )
    assert ticket.covers(now)
    assert not ticket.covers(now + timedelta(hours=1))


def test_patch_verification_marks_200_to_403():
    patch = PatchResult(incident_id="inc_1", target_file="backend/target_service.py")
    patch.mark_verified(200, 403)
    assert patch.verified is True
    assert "PATCH VERIFIED" in patch.verification_note


def test_patch_verification_fails_when_still_leaking():
    patch = PatchResult(incident_id="inc_1", target_file="backend/target_service.py")
    patch.mark_verified(200, 200)
    assert patch.verified is False


def test_incident_bundles_decision_and_actions():
    decision = OODADecision(
        incident_id="inc_1",
        classification=Classification.THREAT_CRITICAL,
        severity=Severity.CRITICAL,
        actions=[MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66")],
    )
    incident = Incident(id="inc_1", scenario="A", decision=decision)
    assert incident.decision.actions[0].action is ActionType.BLOCK_IP_ON_GATEWAY
    assert incident.status.value == "open"
