"""Task 3 — camera tampering must fail closed, never look like an empty seat.

Verified gap before this work: a covered lens produced
``present=False, reliable=True, confidence=0.9, "no operator-sized motion"``.
That is a confident wrong answer, and it let anyone blind the sensor and turn
every privileged command into a ghost-attack verdict (an operational DoS).
"""

from datetime import datetime, timezone

import numpy as np
import pytest

from backend.edge.policy_engine import ChangeTicketStore, PolicyEngine
from backend.models import (
    ActionType,
    Classification,
    MCPAction,
    OODADecision,
    PolicyMode,
    Severity,
    VisionEvidence,
    utc_now,
)
from tests.support import admin_event, network_event, usb_event

TAMPERED = VisionEvidence(
    operator_present=False,
    presence_known=False,
    confidence=0.0,
    roi=[],
    description="camera tampered: lens covered; presence cannot be established",
    method="tamper_check",
    tampered=True,
    tamper_reason="lens covered or camera in the dark (mean 3.2, spread 1.1)",
)

CLEAN_EMPTY_SEAT = VisionEvidence(
    operator_present=False,
    presence_known=True,
    confidence=0.9,
    roi=[],
    description="no operator-sized motion versus the clean baseline",
    method="baseline_diff",
    tampered=False,
)


def decision(confidence: float = 0.93, actions=None) -> OODADecision:
    return OODADecision(
        incident_id="inc_tamper",
        classification=Classification.THREAT_CRITICAL,
        severity=Severity.CRITICAL,
        confidence=confidence,
        actions=actions
        if actions is not None
        else [
            MCPAction(action=ActionType.BLOCK_IP_ON_GATEWAY, target="203.0.113.66"),
            MCPAction(action=ActionType.REVOKE_SESSION_TOKEN, target="session-7f3a9c"),
        ],
    )


def engine() -> PolicyEngine:
    return PolicyEngine(ChangeTicketStore(tickets=[]))


# ------------------------------------------------------------------ policy --

def test_tampered_camera_during_admin_command_fails_closed():
    outcome = engine().evaluate(
        events=[admin_event()],
        proposed=decision(),
        vision=TAMPERED,
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.APPROVAL
    assert outcome.classification is Classification.THREAT_CRITICAL
    assert outcome.severity is Severity.CRITICAL
    assert outcome.approved_actions == []  # nothing runs automatically
    assert outcome.pending_actions  # a human gets something to decide on
    assert "fail-closed" in outcome.reason
    assert "camera tampered" in outcome.reason


def test_tampered_camera_never_auto_contains_even_with_high_confidence():
    outcome = engine().evaluate(
        events=[admin_event()],
        proposed=decision(confidence=0.99),
        vision=TAMPERED,
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.APPROVAL
    assert outcome.approved_actions == []


def test_tampered_camera_does_not_suppress_even_with_a_valid_ticket():
    """A blinded sensor must not become a way to whitelist activity."""
    from tests.support import covering_ticket

    policy = PolicyEngine(ChangeTicketStore(tickets=[covering_ticket(operator="ops-admin")]))
    outcome = policy.evaluate(
        events=[admin_event(session_owner="ops-admin", session_role="admin")],
        proposed=decision(),
        vision=TAMPERED,
        now=utc_now(),
    )

    assert outcome.classification is not Classification.BENIGN_AUTHORIZED
    assert outcome.mode is PolicyMode.APPROVAL


def test_tampered_camera_with_network_exfiltration_keeps_flow_but_records_tamper():
    """No privileged command: the export is still a real event, not a camera game."""
    outcome = engine().evaluate(
        events=[usb_event("/media/usb"), network_event()],
        proposed=decision(),
        vision=TAMPERED,
        now=utc_now(),
    )

    assert outcome.mode is PolicyMode.AUTO
    assert outcome.classification is Classification.THREAT_CRITICAL
    assert outcome.approved_actions


def test_clean_empty_seat_still_produces_a_ghost_attack():
    """Regression: the tamper guard must not block the real ghost path."""
    outcome = engine().evaluate(
        events=[admin_event()],
        proposed=decision(),
        vision=CLEAN_EMPTY_SEAT,
        now=utc_now(),
    )

    assert outcome.classification is Classification.GHOST_ATTACK
    assert outcome.mode is PolicyMode.AUTO


def test_missing_camera_evidence_is_not_treated_as_tampering():
    """No camera at all is "presence unknown", not "camera attacked"."""
    outcome = engine().evaluate(
        events=[network_event()],
        proposed=decision(),
        vision=None,
        now=utc_now(),
    )

    # Normal confidence-band handling, unaffected by the tamper branch.
    assert outcome.mode is PolicyMode.AUTO
    assert outcome.classification is Classification.THREAT_CRITICAL


# ---------------------------------------------------------------- case file --

def test_casefile_records_tamper_evidence():
    from backend.casefile import build_casefile, render_markdown
    from backend.models import Incident

    incident = Incident(id="inc_tamper", scenario="B", vision=TAMPERED)
    document = build_casefile(incident)

    vision = document["vision"]
    assert vision["tampered"] is True
    assert "lens covered" in vision["tamper_reason"]

    markdown = render_markdown(document)
    assert "Camera tampered" in markdown
    assert "lens covered" in markdown


# ------------------------------------------------------------- end to end ----

def test_tampered_frame_produces_approval_through_the_agent():
    """Full OODA pass with a covered lens: no action may be executed."""
    from backend.edge.ooda_agent import OODAAgent
    from backend.llm.mock import MockLLM
    from tests.support import FakeMCP

    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        MockLLM(), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    import asyncio

    incident = asyncio.run(agent.run([admin_event()], TAMPERED, now=utc_now()))

    assert incident.policy.mode is PolicyMode.APPROVAL
    assert incident.status.value == "open"
    assert mcp.calls == []
