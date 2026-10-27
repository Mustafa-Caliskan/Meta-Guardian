from backend.edge.correlator import Correlator
from backend.models import (
    EventSource,
    EventType,
    SecurityEvent,
    Severity,
)
from tests.support import admin_event, network_event, usb_event


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_suspicious_usb_is_held_until_network_arrives():
    clock = FakeClock()
    correlator = Correlator(window_seconds=30, cooldown_seconds=0, clock=clock)

    assert correlator.observe(usb_event()) is None
    assert correlator.pending_count == 1

    clock.advance(2.0)
    result = correlator.observe(network_event())

    assert result is not None
    assert result.reason == "usb_plus_network"
    assert [event.type for event in result.events] == [
        EventType.USB_INSERTED,
        EventType.SUSPICIOUS_API_REQUEST,
    ]
    assert result.latency_ms == 2000.0
    assert correlator.pending_count == 0


def test_usb_payload_alone_is_emitted_after_the_window():
    clock = FakeClock()
    correlator = Correlator(window_seconds=10, cooldown_seconds=0, clock=clock)
    correlator.observe(usb_event())

    clock.advance(5)
    assert correlator.flush() == []

    clock.advance(6)
    results = correlator.flush()
    assert len(results) == 1
    assert results[0].reason == "usb_payload"


def test_clean_usb_insert_does_not_raise_an_incident():
    clock = FakeClock()
    correlator = Correlator(window_seconds=10, cooldown_seconds=0, clock=clock)
    clean = SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        severity=Severity.MEDIUM,
        payload={"mountpoint": "/media/usb", "findings": []},
    )
    assert correlator.observe(clean) is None
    clock.advance(11)
    assert correlator.flush() == []


def test_network_attack_alone_emits_immediately():
    correlator = Correlator()
    result = correlator.observe(network_event())
    assert result is not None
    assert result.reason == "network_attack"
    assert not result.has_usb


def test_admin_command_emits_immediately():
    correlator = Correlator()
    result = correlator.observe(admin_event())
    assert result is not None
    assert result.reason == "admin_command"


def test_repeated_events_are_deduplicated():
    correlator = Correlator()
    first = correlator.observe(network_event())
    assert first is not None
    # Re-observing the same event object must not produce a second bundle.
    assert correlator.observe(first.events[0]) is None


def test_cooldown_suppresses_a_storm_of_identical_signatures():
    clock = FakeClock()
    correlator = Correlator(window_seconds=30, cooldown_seconds=10, clock=clock)

    first = correlator.observe(network_event())
    assert first is not None

    clock.advance(2)
    assert correlator.observe(network_event()) is None

    clock.advance(9)
    second = correlator.observe(network_event())
    assert second is not None


def test_expired_events_are_pruned():
    clock = FakeClock()
    correlator = Correlator(window_seconds=5, cooldown_seconds=0, clock=clock)
    correlator.observe(usb_event())
    clock.advance(30)
    correlator.observe(network_event())
    assert correlator.pending_count <= 1


def test_reset_clears_state():
    correlator = Correlator()
    correlator.observe(network_event())
    correlator.reset()
    assert correlator.pending_count == 0
    assert correlator.last_result is None


def test_invalid_window_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        Correlator(window_seconds=0)
