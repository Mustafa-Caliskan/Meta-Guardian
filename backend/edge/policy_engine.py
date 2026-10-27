"""Deterministic policy engine: the gate between an LLM proposal and reality.

The LLM is allowed to *suggest* containment. This module decides whether the
suggestion is executed, queued for human approval, or only monitored. That
split is what makes the demo defensible: no destructive action can happen just
because a model said so.

Rules:

1. A valid change ticket **and** a visible operator => ``BENIGN_AUTHORIZED``
   (monitor only, zero false alarms).
2. A privileged command with **no** operator => ``GHOST_ATTACK`` (auto contain).
3. Otherwise trust the proposal only within confidence bands:
   ``>= 0.85`` auto, ``0.50-0.85`` approval, ``< 0.50`` monitor.
4. Every executed action must pass a sliding-window rate limit.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from ..config import get_settings
from ..models import (
    ActionType,
    ChangeTicket,
    Classification,
    EventType,
    MCPAction,
    OODADecision,
    PolicyMode,
    PolicyOutcome,
    SecurityEvent,
    Severity,
    VisionEvidence,
    utc_now,
)

DESTRUCTIVE_ACTIONS = {
    ActionType.QUARANTINE_USB_FILE,
    ActionType.BLOCK_IP_ON_GATEWAY,
    ActionType.REVOKE_SESSION_TOKEN,
    ActionType.KILL_PROCESS,
}


class ChangeTicketStore:
    """Loads ``change_tickets.json`` and answers coverage questions."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        tickets: Iterable[ChangeTicket] | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else get_settings().change_tickets_path
        self._tickets: list[ChangeTicket] = []
        self.errors: list[str] = []
        if tickets is not None:
            self._tickets = list(tickets)
        else:
            self.load()

    @property
    def tickets(self) -> list[ChangeTicket]:
        return list(self._tickets)

    def load(self) -> None:
        self._tickets = []
        self.errors = []
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"cannot read {self.path}: {exc}")
            return

        items = raw.get("tickets") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            self.errors.append("change ticket file must contain a list")
            return

        for index, item in enumerate(items):
            if not isinstance(item, dict):
                self.errors.append(f"ticket[{index}] is not an object")
                continue
            try:
                self._tickets.append(ChangeTicket(**item))
            except Exception as exc:  # noqa: BLE001 - report, never crash
                self.errors.append(f"ticket[{index}]: {exc}")

    def add(self, ticket: ChangeTicket) -> None:
        self._tickets.append(ticket)

    def replace(self, tickets: Iterable[ChangeTicket]) -> None:
        self._tickets = list(tickets)

    def find_covering(self, moment: datetime | None = None) -> ChangeTicket | None:
        moment = moment or utc_now()
        for ticket in self._tickets:
            if ticket.covers(moment):
                return ticket
        return None

    def is_authorized(
        self, moment: datetime | None = None, *, operator_present: bool
    ) -> tuple[ChangeTicket | None, str]:
        moment = moment or utc_now()
        if not operator_present:
            return None, "no operator visible in the camera frame"
        ticket = self.find_covering(moment)
        if ticket is None:
            return None, "no approved change ticket covers this window"
        if not ticket.usb_allowed and ticket.reason.lower().startswith("usb"):
            return None, f"ticket {ticket.ticket_id} does not allow USB activity"
        return ticket, f"approved ticket {ticket.ticket_id} ({ticket.operator})"


class SlidingWindowRateLimiter:
    def __init__(
        self,
        max_events: int = 30,
        window_seconds: float = 60.0,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_events = max(1, int(max_events))
        self.window_seconds = float(window_seconds)
        self._clock = clock or time.monotonic
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            cutoff = now - self.window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


def _ensure_tz(value: datetime | None) -> datetime:
    if value is None:
        return utc_now()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class PolicyEngine:
    def __init__(
        self,
        tickets: ChangeTicketStore | None = None,
        *,
        min_auto_confidence: float = 0.85,
        min_approval_confidence: float = 0.50,
        rate_limiter: SlidingWindowRateLimiter | None = None,
    ) -> None:
        if not 0.0 <= min_approval_confidence <= min_auto_confidence <= 1.0:
            raise ValueError("confidence thresholds must satisfy 0 <= approval <= auto <= 1")
        self.tickets = tickets or ChangeTicketStore()
        self.min_auto_confidence = min_auto_confidence
        self.min_approval_confidence = min_approval_confidence
        settings = get_settings()
        self.rate_limiter = rate_limiter or SlidingWindowRateLimiter(
            max_events=settings.max_actions_per_minute, window_seconds=60.0
        )

    # -- public API ----------------------------------------------------------

    def evaluate(
        self,
        *,
        events: list[SecurityEvent],
        proposed: OODADecision,
        vision: VisionEvidence | None = None,
        now: datetime | None = None,
    ) -> PolicyOutcome:
        moment = _ensure_tz(now)
        presence_known = bool(vision and vision.presence_known)
        operator_present = bool(vision and vision.operator_present)
        has_admin = any(event.type is EventType.ADMIN_COMMAND for event in events)
        ticket = self.tickets.find_covering(moment)

        if ticket is not None and operator_present:
            return self._authorized(proposed, ticket, operator_present, moment)

        if has_admin and presence_known and not operator_present:
            return self._ghost(proposed, events, operator_present, moment)

        classification = proposed.classification
        if classification is Classification.BENIGN_AUTHORIZED:
            # Deterministic override: an LLM cannot whitelist an event on its own.
            classification = Classification.BENIGN_UNKNOWN
        if classification in (Classification.BENIGN_AUTHORIZED, Classification.BENIGN_UNKNOWN):
            return PolicyOutcome(
                classification=classification,
                severity=proposed.severity,
                confidence=proposed.confidence,
                mode=PolicyMode.MONITOR,
                reason="benign classification: monitor only, no destructive actions",
                operator_present=operator_present,
                evaluated_at=moment,
            )

        actions = self._candidate_actions(proposed, events)
        confidence = max(0.0, min(1.0, float(proposed.confidence)))

        if not actions:
            return PolicyOutcome(
                classification=classification,
                severity=proposed.severity,
                confidence=confidence,
                mode=PolicyMode.MONITOR,
                reason="no containment action proposed",
                operator_present=operator_present,
                evaluated_at=moment,
            )

        if confidence >= self.min_auto_confidence:
            approved, limited = self._rate_limit(actions)
            mode = PolicyMode.AUTO
            reason = (
                f"confidence {confidence:.2f} >= {self.min_auto_confidence:.2f}: "
                "auto containment"
            )
            return PolicyOutcome(
                classification=classification,
                severity=proposed.severity,
                confidence=confidence,
                mode=mode,
                reason=reason,
                operator_present=operator_present,
                approved_actions=approved,
                rate_limited_actions=limited,
                evaluated_at=moment,
            )

        if confidence >= self.min_approval_confidence:
            return PolicyOutcome(
                classification=classification,
                severity=proposed.severity,
                confidence=confidence,
                mode=PolicyMode.APPROVAL,
                reason=(
                    f"confidence {confidence:.2f} in "
                    f"[{self.min_approval_confidence:.2f}, {self.min_auto_confidence:.2f}): "
                    "human approval required"
                ),
                operator_present=operator_present,
                pending_actions=actions,
                evaluated_at=moment,
            )

        return PolicyOutcome(
            classification=classification,
            severity=proposed.severity,
            confidence=confidence,
            mode=PolicyMode.MONITOR,
            reason=f"confidence {confidence:.2f} < {self.min_approval_confidence:.2f}: monitor",
            operator_present=operator_present,
            pending_actions=actions,
            evaluated_at=moment,
        )

    # -- rules ---------------------------------------------------------------

    def _authorized(
        self,
        proposed: OODADecision,
        ticket: ChangeTicket,
        operator_present: bool,
        moment: datetime,
    ) -> PolicyOutcome:
        return PolicyOutcome(
            classification=Classification.BENIGN_AUTHORIZED,
            severity=Severity.LOW,
            confidence=max(proposed.confidence, 0.95),
            mode=PolicyMode.MONITOR,
            reason=(
                f"change ticket {ticket.ticket_id} by {ticket.operator} covers "
                f"{moment.isoformat()} and an operator is present"
            ),
            ticket_id=ticket.ticket_id,
            operator_present=operator_present,
            evaluated_at=moment,
        )

    def _ghost(
        self,
        proposed: OODADecision,
        events: list[SecurityEvent],
        operator_present: bool,
        moment: datetime,
    ) -> PolicyOutcome:
        actions = self._candidate_actions(proposed, events)
        if not actions:
            actions = self.default_containment(events)
        approved, limited = self._rate_limit(actions)
        return PolicyOutcome(
            classification=Classification.GHOST_ATTACK,
            severity=Severity.CRITICAL,
            confidence=max(proposed.confidence, 0.95),
            mode=PolicyMode.AUTO,
            reason=(
                "privileged command executed while no operator was visible: "
                "remote ghost attack"
            ),
            operator_present=operator_present,
            approved_actions=approved,
            rate_limited_actions=limited,
            evaluated_at=moment,
        )

    # -- helpers -------------------------------------------------------------

    def _candidate_actions(
        self, proposed: OODADecision, events: list[SecurityEvent]
    ) -> list[MCPAction]:
        actions = [
            action for action in proposed.actions if action.action in DESTRUCTIVE_ACTIONS
        ]
        if not actions and proposed.classification in (
            Classification.THREAT_CRITICAL,
            Classification.GHOST_ATTACK,
        ):
            actions = self.default_containment(events)
        return _dedupe(actions)

    def _rate_limit(
        self, actions: list[MCPAction]
    ) -> tuple[list[MCPAction], list[MCPAction]]:
        approved: list[MCPAction] = []
        limited: list[MCPAction] = []
        for action in actions:
            key = action.action.value
            if self.rate_limiter.allow(key):
                approved.append(action)
            else:
                limited.append(action)
        return approved, limited

    @staticmethod
    def default_containment(events: list[SecurityEvent]) -> list[MCPAction]:
        actions: list[MCPAction] = []
        for event in events:
            payload = event.payload or {}
            if event.type is EventType.USB_INSERTED:
                mountpoint = payload.get("mountpoint")
                for finding in payload.get("findings") or []:
                    name = finding.get("name")
                    if mountpoint and name:
                        actions.append(
                            MCPAction(
                                action=ActionType.QUARANTINE_USB_FILE,
                                target=name,
                                reason="suspicious file on removable media",
                                metadata={"drive_path": mountpoint},
                            )
                        )
        for event in events:
            payload = event.payload or {}
            ip = payload.get("ip")
            if ip and ip not in ("-", "unknown"):
                actions.append(
                    MCPAction(
                        action=ActionType.BLOCK_IP_ON_GATEWAY,
                        target=str(ip),
                        reason="source of suspicious request",
                    )
                )
            session = payload.get("session")
            if session and session not in ("-", "unknown"):
                actions.append(
                    MCPAction(
                        action=ActionType.REVOKE_SESSION_TOKEN,
                        target=str(session),
                        reason="session used by the attacker",
                    )
                )
        return _dedupe(actions)


def _dedupe(actions: list[MCPAction]) -> list[MCPAction]:
    seen: set[tuple[str, str]] = set()
    unique: list[MCPAction] = []
    for action in actions:
        key = (action.action.value, action.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique


__all__ = [
    "ChangeTicketStore",
    "PolicyEngine",
    "SlidingWindowRateLimiter",
    "DESTRUCTIVE_ACTIONS",
]
