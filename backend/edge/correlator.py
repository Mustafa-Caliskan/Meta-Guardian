"""Event correlation: turns raw edge telemetry into incident bundles.

This is the missing link between the watchers and the OODA agent. The watchers
publish individual ``SecurityEvent`` objects; this correlator decides when a
group of events is a single incident worth waking the agent for.

Rules (all deterministic, all testable):

* **USB + network within the window** -> ``usb_plus_network`` (Scenario A).
* **Privileged admin command** -> ``admin_command`` immediately.
* **Critical exfiltration request alone** -> ``network_attack`` immediately.
* **Suspicious USB payload alone** -> held for ``window_seconds`` and emitted as
  ``usb_payload`` if nothing else corroborates it (avoids missing a dead-drop).

A short per-signature cooldown prevents an event storm from spawning the same
incident repeatedly.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable

from ..models import EventSource, EventType, SecurityEvent, Severity


@dataclass
class CorrelationResult:
    events: list[SecurityEvent]
    reason: str
    opened_at: float
    closed_at: float
    signature: str
    latency_ms: float = 0.0

    @property
    def event_ids(self) -> list[str]:
        return [event.id for event in self.events]

    @property
    def has_usb(self) -> bool:
        return any(event.type is EventType.USB_INSERTED for event in self.events)

    def summary(self) -> str:
        return f"{self.reason}: {len(self.events)} event(s)"


def _is_suspicious_usb(event: SecurityEvent) -> bool:
    if event.type is not EventType.USB_INSERTED:
        return False
    findings = (event.payload or {}).get("findings") or []
    return bool(findings)


def _is_attack_network(event: SecurityEvent) -> bool:
    if event.type in (EventType.SUSPICIOUS_API_REQUEST, EventType.ADMIN_COMMAND):
        return True
    return event.source is EventSource.NETWORK and event.severity in (
        Severity.HIGH,
        Severity.CRITICAL,
    )


def _event_key(event: SecurityEvent) -> str:
    payload = event.payload or {}
    target = (
        payload.get("mountpoint")
        or payload.get("ip")
        or payload.get("path")
        or ""
    )
    return f"{event.type.value}:{target}"


class Correlator:
    def __init__(
        self,
        *,
        window_seconds: float = 30.0,
        cooldown_seconds: float = 10.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = float(window_seconds)
        self.cooldown_seconds = float(cooldown_seconds)
        self._clock = clock or time.monotonic
        self._pending: list[tuple[SecurityEvent, float]] = []
        self._emitted: set[str] = set()
        self._last_emit: dict[str, float] = {}
        self.last_result: CorrelationResult | None = None

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def reset(self) -> None:
        self._pending.clear()
        self._emitted.clear()
        self._last_emit.clear()
        self.last_result = None

    def observe(self, event: SecurityEvent) -> CorrelationResult | None:
        now = self._clock()
        if event.id in self._emitted:
            return None

        self._pending.append((event, now))
        self._expire(now)

        result = self._try_emit(now, trigger=event)
        if result is not None:
            self._consume(result, now)
        return result

    def flush(self) -> list[CorrelationResult]:
        """Emit held USB-only bundles whose window has expired."""
        now = self._clock()
        results: list[CorrelationResult] = []
        expired = [
            (event, stamp) for event, stamp in self._pending if now - stamp >= self.window_seconds
        ]
        for event, stamp in expired:
            if event.id in self._emitted:
                continue
            if _is_suspicious_usb(event):
                result = self._make_result(
                    [event], reason="usb_payload", opened_at=stamp, now=now
                )
                if self._cooldown_ok(result.signature, now):
                    self._consume(result, now)
                    results.append(result)
        self._pending = [
            (event, stamp)
            for event, stamp in self._pending
            if now - stamp < self.window_seconds and event.id not in self._emitted
        ]
        return results

    # -- internals -----------------------------------------------------------

    def _expire(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._pending = [
            (event, stamp)
            for event, stamp in self._pending
            if stamp >= cutoff and event.id not in self._emitted
        ]

    def _try_emit(self, now: float, trigger: SecurityEvent) -> CorrelationResult | None:
        relevant = [event for event, _ in self._pending if event.id not in self._emitted]
        if not relevant:
            return None

        stamps = {event.id: stamp for event, stamp in self._pending}
        window_events = [
            event
            for event in relevant
            if now - stamps.get(event.id, now) <= self.window_seconds
        ]

        has_admin = any(event.type is EventType.ADMIN_COMMAND for event in window_events)
        has_usb = any(_is_suspicious_usb(event) for event in window_events)
        has_net = any(
            _is_attack_network(event)
            and event.type is not EventType.ADMIN_COMMAND
            for event in window_events
        )

        if trigger.type is EventType.ADMIN_COMMAND:
            reason = "admin_command"
        elif trigger.type is EventType.SUSPICIOUS_API_REQUEST and has_usb:
            reason = "usb_plus_network"
        elif trigger.type is EventType.SUSPICIOUS_API_REQUEST:
            reason = "network_attack"
        elif trigger.type is EventType.USB_INSERTED and has_net:
            reason = "usb_plus_network"
        elif trigger.type is EventType.USB_INSERTED:
            return None  # hold for the window
        elif has_admin:
            reason = "admin_command"
        elif has_usb and has_net:
            reason = "usb_plus_network"
        else:
            return None

        if reason == "admin_command":
            bundle = [event for event in window_events if event.type is EventType.ADMIN_COMMAND]
            bundle = sorted(bundle or [trigger], key=lambda e: e.timestamp)
        elif reason == "usb_plus_network":
            bundle = [event for event in window_events if _is_suspicious_usb(event) or _is_attack_network(event)]
        else:
            bundle = [event for event in window_events if _is_attack_network(event)]

        bundle = bundle or [trigger]
        opened_at = min(stamps.get(event.id, now) for event in bundle)
        result = self._make_result(bundle, reason=reason, opened_at=opened_at, now=now)

        if not self._cooldown_ok(result.signature, now):
            for event in bundle:
                self._emitted.add(event.id)
            return None
        return result

    def _make_result(
        self,
        events: list[SecurityEvent],
        *,
        reason: str,
        opened_at: float,
        now: float,
    ) -> CorrelationResult:
        ordered = sorted(events, key=lambda event: event.timestamp)
        signature_source = "|".join(_event_key(event) for event in ordered)
        signature = hashlib.sha1(
            f"{reason}:{signature_source}".encode("utf-8")
        ).hexdigest()[:16]
        return CorrelationResult(
            events=ordered,
            reason=reason,
            opened_at=opened_at,
            closed_at=now,
            signature=signature,
            latency_ms=round((now - opened_at) * 1000, 2),
        )

    def _cooldown_ok(self, signature: str, now: float) -> bool:
        last = self._last_emit.get(signature)
        if last is not None and now - last < self.cooldown_seconds:
            return False
        return True

    def _consume(self, result: CorrelationResult, now: float) -> None:
        for event in result.events:
            self._emitted.add(event.id)
        self._pending = [
            (event, stamp) for event, stamp in self._pending if event.id not in self._emitted
        ]
        self._last_emit[result.signature] = now
        self.last_result = result


__all__ = ["Correlator", "CorrelationResult"]
