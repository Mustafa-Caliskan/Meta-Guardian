"""Task 4 — console collision / CREDENTIAL_MISUSE.

A privileged command authenticated by a real admin token but issued from a
remote origin *while somebody is sitting at the console* is a different story
from an empty chair: the log looks identical to the real operator's own work.
The camera is the only signal that separates them. Because that signal is a
contradiction rather than proof, the verdict must always be human approval and
never automatic containment.
"""

from datetime import timedelta

from backend.edge.policy_engine import (
    LOCAL,
    MANAGEMENT,
    REMOTE,
    UNKNOWN_ORIGIN,
    ChangeTicketStore,
    PolicyEngine,
    origin_scope,
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
from tests.support import admin_event, covering_ticket, vision

MGMT = ["10.0.0.0/8"]


def decision(confidence: float = 0.93) -> OODADecision:
    return OODADecision(
        incident_id="inc_misuse",
        classification=Classification.THREAT_CRITICAL,
        severity=Severity.CRITICAL,
        confidence=confidence,
        actions=[
            MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66"),
            MCPAction(action=ActionType.REVOKE_SESSION_TOKEN, target="session-7f3a9c"),
        ],
    )


def engine(ticket: ChangeTicket | None = None, networks=MGMT) -> PolicyEngine:
    return PolicyEngine(
        ChangeTicketStore(tickets=[ticket] if ticket else []),
        management_networks=networks,
    )


# ------------------------------------------------------ origin classification --

def test_origin_scope_classifies_loopback_management_and_remote():
    assert origin_scope("127.0.0.1", MGMT) == LOCAL
    assert origin_scope("::1", MGMT) == LOCAL
    assert origin_scope("10.0.0.31", MGMT) == MANAGEMENT
    assert origin_scope("203.0.113.66", MGMT) == REMOTE
    assert origin_scope("not-an-ip", MGMT) == UNKNOWN_ORIGIN
    assert origin_scope(None, MGMT) == UNKNOWN_ORIGIN


def test_management_networks_default_to_empty_so_private_is_remote():
    assert origin_scope("10.0.0.31", []) == REMOTE


# ------------------------------------------------------------ the four rows --

def test_row1_ticket_owner_equal_session_and_management_origin_while_seat_is_empty():
    """Legit remote IT: correct owner, known management source, empty chair."""
    now = utc_now()
    outcome = engine(covering_ticket(operator="ops-admin")).evaluate(
        events=[admin_event(session_owner="ops-admin", session_origin_ip="10.0.0.31")],
        proposed=decision(),
        vision=vision(False),
        now=now,
    )

    assert outcome.classification is Classification.BENIGN_AUTHORIZED
    assert outcome.mode is PolicyMode.MONITOR
    assert outcome.ticket_owner_match is True
    assert outcome.approved_actions == []
    assert "known management source" in outcome.reason


def test_row2_no_ticket_admin_remote_origin_with_operator_present_is_credential_misuse():
    outcome = engine().evaluate(
        events=[admin_event(session_origin_ip="203.0.113.66")],
        proposed=decision(confidence=1.0),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is Classification.CREDENTIAL_MISUSE
    assert outcome.mode is PolicyMode.APPROVAL
    assert outcome.approved_actions == []
    assert outcome.pending_actions
    assert outcome.session_origin_ip == "203.0.113.66"
    assert "credential misuse" in outcome.reason.lower()


def test_row2_misuse_never_auto_contains_even_at_max_confidence():
    outcome = engine().evaluate(
        events=[admin_event(session_origin_ip="198.51.100.7")],
        proposed=decision(confidence=1.0),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.APPROVAL
    assert outcome.approved_actions == []


def test_row3_no_ticket_admin_empty_seat_is_ghost_attack_auto():
    outcome = engine().evaluate(
        events=[admin_event()],
        proposed=decision(),
        vision=vision(False),
        now=utc_now(),
    )

    assert outcome.classification is Classification.GHOST_ATTACK
    assert outcome.mode is PolicyMode.AUTO


def test_row4_no_ticket_admin_local_origin_with_operator_present_is_threat_critical():
    outcome = engine().evaluate(
        events=[admin_event(session_origin_ip="127.0.0.1")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is Classification.THREAT_CRITICAL
    assert outcome.mode is PolicyMode.AUTO


# ------------------------------------------------------------- edge cases ----

def test_management_origin_with_operator_present_is_not_misuse():
    outcome = engine().evaluate(
        events=[admin_event(session_origin_ip="10.0.0.31")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is Classification.THREAT_CRITICAL
    assert outcome.mode is PolicyMode.AUTO


def test_unknown_origin_with_operator_present_is_not_misuse():
    outcome = engine().evaluate(
        events=[admin_event(session_origin_ip="")],
        proposed=decision(),
        vision=vision(True),
        now=utc_now(),
    )

    assert outcome.classification is not Classification.CREDENTIAL_MISUSE


def test_wrong_owner_ticket_does_not_authorise_remote_management_work():
    outcome = engine(covering_ticket(operator="ops-engineer")).evaluate(
        events=[admin_event(session_owner="ops-admin", session_origin_ip="10.0.0.31")],
        proposed=decision(),
        vision=vision(False),
        now=utc_now(),
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.classification is Classification.GHOST_ATTACK


def test_expired_ticket_does_not_authorise_remote_management_work():
    now = utc_now()
    expired = ChangeTicket(
        ticket_id="CHG-OLD",
        operator="ops-admin",
        reason="past window",
        window_start=now - timedelta(hours=5),
        window_end=now - timedelta(hours=4),
        usb_allowed=True,
    )
    outcome = engine(expired).evaluate(
        events=[admin_event(session_owner="ops-admin", session_origin_ip="10.0.0.31")],
        proposed=decision(),
        vision=vision(False),
        now=now,
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
