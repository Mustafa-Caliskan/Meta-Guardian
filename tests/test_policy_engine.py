import json
from datetime import timedelta
from pathlib import Path

from backend.edge.policy_engine import (
    ChangeTicketStore,
    PolicyEngine,
    SlidingWindowRateLimiter,
)
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
from tests.support import (
    admin_event,
    covering_ticket,
    network_event,
    usb_event,
    vision,
)


def decision(
    *,
    classification: Classification = Classification.THREAT_CRITICAL,
    confidence: float = 0.9,
    actions: list[MCPAction] | None = None,
) -> OODADecision:
    return OODADecision(
        incident_id="inc_test",
        classification=classification,
        severity=Severity.CRITICAL,
        confidence=confidence,
        actions=actions or [],
    )


def default_actions() -> list[MCPAction]:
    return [
        MCPAction(action=ActionType.QUARANTINE_USB_FILE, target="payload.ps1"),
        MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66"),
        MCPAction(action=ActionType.REVOKE_SESSION_TOKEN, target="session-7f3a9c"),
    ]


def test_high_confidence_is_auto_contained():
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[usb_event(), network_event()],
        proposed=decision(confidence=0.93, actions=default_actions()),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.AUTO
    assert len(outcome.approved_actions) == 3
    assert outcome.pending_actions == []
    assert outcome.classification is Classification.THREAT_CRITICAL


def test_mid_confidence_requires_approval():
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[usb_event()],
        proposed=decision(confidence=0.62, actions=default_actions()),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.APPROVAL
    assert outcome.approved_actions == []
    assert len(outcome.pending_actions) == 3


def test_low_confidence_monitors_only():
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[usb_event()],
        proposed=decision(confidence=0.31, actions=default_actions()),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.MONITOR
    assert outcome.approved_actions == []
    assert len(outcome.pending_actions) == 3


def test_valid_ticket_and_operator_is_benign_authorized():
    now = utc_now()
    store = ChangeTicketStore(tickets=[covering_ticket()])
    engine = PolicyEngine(store)

    outcome = engine.evaluate(
        events=[usb_event(), network_event()],
        proposed=decision(confidence=0.99, actions=default_actions()),
        vision=vision(True),
        now=now,
    )

    assert outcome.classification is Classification.BENIGN_AUTHORIZED
    assert outcome.mode is PolicyMode.MONITOR
    assert outcome.approved_actions == []
    assert outcome.ticket_id is not None


def test_ticket_without_operator_is_not_authorized():
    now = utc_now()
    store = ChangeTicketStore(tickets=[covering_ticket()])
    engine = PolicyEngine(store)

    outcome = engine.evaluate(
        events=[network_event()],
        proposed=decision(confidence=0.93, actions=default_actions()),
        vision=vision(False),
        now=now,
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.ticket_id is None


def test_admin_command_without_operator_is_ghost_attack():
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[admin_event()],
        proposed=decision(
            classification=Classification.BENIGN_UNKNOWN,
            confidence=0.1,
            actions=[],
        ),
        vision=vision(False),
        now=utc_now(),
    )

    assert outcome.classification is Classification.GHOST_ATTACK
    assert outcome.mode is PolicyMode.AUTO
    assert outcome.severity is Severity.CRITICAL
    assert {action.action for action in outcome.approved_actions} >= {
        ActionType.BLOCK_IP_ON_GATEWAY,
        ActionType.REVOKE_SESSION_TOKEN,
    }


def test_llm_cannot_whitelist_without_ticket():
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[usb_event()],
        proposed=decision(
            classification=Classification.BENIGN_AUTHORIZED, confidence=0.99
        ),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is Classification.BENIGN_UNKNOWN
    assert outcome.mode is PolicyMode.MONITOR
    assert outcome.approved_actions == []


def test_trusted_classification_with_no_actionable_evidence_monitors():
    from backend.models import EventSource, EventType, SecurityEvent

    empty_event = SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        payload={"mountpoint": "/media/usb", "findings": []},
    )
    engine = PolicyEngine(ChangeTicketStore(tickets=[]))
    outcome = engine.evaluate(
        events=[empty_event],
        proposed=decision(confidence=0.93, actions=[]),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.MONITOR
    assert "no containment action" in outcome.reason


def test_rate_limiter_trips():
    limiter = SlidingWindowRateLimiter(max_events=1, window_seconds=60)
    engine = PolicyEngine(ChangeTicketStore(tickets=[]), rate_limiter=limiter)

    actions = [
        MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.1"),
        MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.2"),
    ]
    outcome = engine.evaluate(
        events=[network_event()],
        proposed=decision(confidence=0.95, actions=actions),
        vision=vision(True),
        now=utc_now(),
    )

    assert len(outcome.approved_actions) == 1
    assert len(outcome.rate_limited_actions) == 1


def test_rate_limiter_window_slides():
    clock = {"now": 1000.0}
    limiter = SlidingWindowRateLimiter(
        max_events=1, window_seconds=10, clock=lambda: clock["now"]
    )
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    clock["now"] += 11
    assert limiter.allow("k") is True


def test_ticket_store_loads_and_skips_invalid(tmp_path: Path):
    ticket = covering_ticket().model_dump(mode="json")
    path = tmp_path / "tickets.json"
    path.write_text(
        json.dumps({"tickets": [ticket, {"ticket_id": "broken"}]}), encoding="utf-8"
    )

    store = ChangeTicketStore(path)
    assert len(store.tickets) == 1
    assert store.errors and "ticket[1]" in store.errors[0]
    assert store.find_covering(utc_now()) is not None


def test_ticket_store_missing_file_is_empty(tmp_path: Path):
    store = ChangeTicketStore(tmp_path / "missing.json")
    assert store.tickets == []
    assert store.errors == []


def test_ticket_store_detects_outside_window(tmp_path: Path):
    ticket = covering_ticket()
    store = ChangeTicketStore(tickets=[ticket])
    assert store.find_covering(utc_now() + timedelta(hours=5)) is None


def test_invalid_thresholds_are_rejected():
    import pytest

    with pytest.raises(ValueError):
        PolicyEngine(min_auto_confidence=0.4, min_approval_confidence=0.9)
