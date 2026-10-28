from datetime import timedelta

import pytest

from backend.edge.ooda_agent import OODAAgent, build_agent
from backend.edge.policy_engine import ChangeTicketStore, PolicyEngine
from backend.llm.mock import MockLLM
from backend.models import (
    Classification,
    Severity,
    EventSource,
    EventType,
    IncidentStatus,
    PolicyMode,
    SecurityEvent,
    utc_now,
)
from tests.support import (
    FakeMCP,
    StubLLM,
    admin_event,
    covering_ticket,
    network_event,
    usb_event,
    vision,
)


def make_agent(**kwargs) -> tuple[OODAAgent, FakeMCP]:
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=kwargs.pop("tickets", []))
    agent = OODAAgent(
        MockLLM(), policy=PolicyEngine(store), mcp=mcp, change_tickets=store, **kwargs
    )
    return agent, mcp


async def test_scenario_a_end_to_end_containment():
    agent, mcp = make_agent()
    events = [usb_event(mountpoint="/media/usb"), network_event()]

    incident = await agent.run(events, vision(True), now=utc_now())

    assert incident.scenario == "A"
    assert incident.status is IncidentStatus.CONTAINED
    assert incident.decision.classification is Classification.THREAT_CRITICAL
    assert incident.policy.mode is PolicyMode.AUTO
    assert len(incident.action_results) == 3
    assert all(result.success for result in incident.action_results)

    calls = dict((name, args) for name, args in mcp.calls)
    assert calls["quarantine_usb_file"] == {
        "drive_path": "/media/usb",
        "filename": "payload.ps1",
    }
    assert calls["block_ip_on_gateway"] == {"ip": "203.0.113.66"}
    assert calls["revoke_session_token"] == {"session": "session-7f3a9c"}


async def test_scenario_b_ghost_attack_without_operator():
    agent, mcp = make_agent()
    events = [admin_event()]

    incident = await agent.run(events, vision(False), now=utc_now())

    assert incident.scenario == "B"
    assert incident.decision.classification is Classification.GHOST_ATTACK
    assert incident.policy.mode is PolicyMode.AUTO
    assert incident.status is IncidentStatus.CONTAINED
    executed = {name for name, _ in mcp.calls}
    assert executed == {"block_ip_on_gateway", "revoke_session_token"}


async def test_scenario_c_authorized_maintenance_is_dismissed():
    now = utc_now()
    agent, mcp = make_agent(tickets=[covering_ticket()])

    incident = await agent.run(
        [usb_event(), network_event()], vision(True), now=now
    )

    assert incident.scenario == "C"
    assert incident.decision.classification is Classification.BENIGN_AUTHORIZED
    assert incident.policy.mode is PolicyMode.MONITOR
    assert incident.status is IncidentStatus.DISMISSED
    assert mcp.calls == []


async def test_mid_confidence_queues_for_approval_and_does_not_act():
    now = utc_now()
    payload = {
        "classification": "THREAT_CRITICAL",
        "severity": "high",
        "confidence": 0.62,
        "reasoning": "suspicious but not conclusive",
        "evidence_summary": "usb",
        "actions": [
            {"action": "block_ip_on_gateway", "target": "203.0.113.66", "reason": "src"}
        ],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    incident = await agent.run([network_event()], vision(True), now=now)

    assert incident.policy.mode is PolicyMode.APPROVAL
    assert incident.status is IncidentStatus.OPEN
    assert len(incident.policy.pending_actions) == 1
    assert mcp.calls == []


async def test_llm_failure_degrades_to_monitor():
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(error=RuntimeError("provider down")),
        policy=PolicyEngine(store),
        mcp=mcp,
        change_tickets=store,
    )

    incident = await agent.run([usb_event()], vision(True), now=utc_now())

    assert incident.decision.model == "fallback"
    assert incident.policy.classification is Classification.BENIGN_UNKNOWN
    assert incident.status is IncidentStatus.DISMISSED
    assert "provider down" in incident.decision.reasoning
    assert mcp.calls == []


async def test_mcp_failure_keeps_incident_open():
    agent, _ = make_agent()
    agent.mcp = FakeMCP(success=False)

    incident = await agent.run([usb_event(), network_event()], vision(True), now=utc_now())

    assert incident.status is IncidentStatus.OPEN
    assert incident.action_results
    assert all(not result.success for result in incident.action_results)


async def test_unknown_actions_are_dropped_and_targets_enriched():
    now = utc_now()
    payload = {
        "classification": "THREAT_CRITICAL",
        "severity": "critical",
        "confidence": 0.95,
        "reasoning": "exfil",
        "evidence_summary": "net",
        "actions": [
            {"action": "format_disk", "target": "/dev/sda"},
            {"action": "block_ip_on_gateway", "target": "", "reason": "src"},
            {"action": "quarantine_usb_file", "target": "payload.ps1"},
        ],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    incident = await agent.run([network_event()], vision(True), now=now)

    assert incident.decision.actions[0].action.value == "block_ip_on_gateway"
    assert incident.decision.actions[0].target == "203.0.113.66"
    assert "Enrichment dropped" in incident.decision.reasoning
    assert len(incident.action_results) == 1


async def test_quarantine_without_mountpoint_is_dropped():
    now = utc_now()
    event = SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        payload={"findings": [{"name": "payload.ps1", "sha256": "a" * 64}]},
    )
    payload = {
        "classification": "THREAT_CRITICAL",
        "severity": "high",
        "confidence": 0.95,
        "actions": [
            {"action": "quarantine_usb_file", "target": "payload.ps1"},
        ],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    incident = await agent.run([event], vision(True), now=now)

    assert mcp.calls == []
    assert "no mounted drive path" in incident.decision.reasoning


async def test_run_requires_events():
    agent, _ = make_agent()
    with pytest.raises(ValueError):
        await agent.run([], vision(True), now=utc_now())


def test_build_evidence_includes_ticket_and_vision():
    now = utc_now()
    store = ChangeTicketStore(tickets=[covering_ticket()])
    agent = OODAAgent(MockLLM(), policy=PolicyEngine(store), change_tickets=store)

    evidence = agent.build_evidence([usb_event()], vision(True), now)

    assert evidence["operator_present"] is True
    assert evidence["change_ticket_valid"] is True
    assert evidence["change_ticket"]["ticket_id"] == "CHG-2026-77"
    assert evidence["event_count"] == 1
    assert evidence["events"][0]["type"] == "usb_inserted"
    assert evidence["events"][0]["findings"][0]["name"] == "payload.ps1"


def test_build_agent_helper():
    agent = build_agent(MockLLM())
    assert isinstance(agent, OODAAgent)
    assert agent.policy is not None


def test_scenario_detection_mapping():
    assert OODAAgent._scenario_for(Classification.THREAT_CRITICAL, "unknown") == "A"
    assert OODAAgent._scenario_for(Classification.GHOST_ATTACK, "unknown") == "B"
    assert OODAAgent._scenario_for(Classification.BENIGN_AUTHORIZED, "unknown") == "C"
    assert OODAAgent._scenario_for(Classification.BENIGN_UNKNOWN, "unknown") == "unknown"


async def test_hallucinated_ip_and_session_are_replaced_with_evidence():
    now = utc_now()
    payload = {
        "classification": "THREAT_CRITICAL",
        "severity": "critical",
        "confidence": 0.95,
        "actions": [
            {"action": "block_ip_on_gateway", "target": "198.51.100.99"},
            {"action": "revoke_session_token", "target": "session-invented"},
        ],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    await agent.run([network_event(ip="203.0.113.66", session="session-real")], vision(True), now=now)

    targets = {name: args for name, args in mcp.calls}
    assert targets["block_ip_on_gateway"] == {"ip": "203.0.113.66"}
    assert targets["revoke_session_token"] == {"session": "session-real"}


async def test_llm_ghost_claim_with_unknown_presence_requires_approval():
    from backend.models import VisionEvidence

    unknown = VisionEvidence(
        operator_present=False,
        confidence=0.2,
        description="scene mismatch: presence unknown",
        presence_known=False,
    )
    payload = {
        "classification": "GHOST_ATTACK",
        "severity": "critical",
        "confidence": 0.93,
        "reasoning": "no operator",
        "actions": [
            {"action": "revoke_session_token", "target": "session-7f3a9c"},
        ],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    incident = await agent.run([admin_event()], unknown, now=utc_now())

    assert incident.policy.mode is PolicyMode.APPROVAL
    assert incident.decision.classification is Classification.THREAT_CRITICAL
    assert incident.status is IncidentStatus.OPEN
    assert mcp.calls == []


async def test_scenario_key_is_used_for_the_llm_task():
    class TaskAwareLLM(StubLLM):
        def __init__(self):
            super().__init__({"classification": "THREAT_CRITICAL", "confidence": 0.93})
            self.tasks = []

        async def complete(self, messages, *, task="", **kwargs):
            self.tasks.append(task)
            return await super().complete(messages, task=task, **kwargs)

    llm = TaskAwareLLM()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(llm, policy=PolicyEngine(store), change_tickets=store)

    await agent.run([usb_event()], vision(True), now=utc_now(), scenario="A")
    await agent.run([admin_event()], vision(False), now=utc_now(), scenario="B")

    assert llm.tasks == ["ooda:A", "ooda:B"]


def test_replay_fixtures_distinguish_scenarios():
    from backend.config import FIXTURES_DIR
    from backend.llm.replay import ReplayLLM

    llm = ReplayLLM(FIXTURES_DIR)
    import asyncio

    async def classify(task):
        payload, _ = await llm.complete_json([{"role": "user", "content": "x"}], task=task)
        return payload.get("classification")

    assert asyncio.run(classify("ooda:A")) == "THREAT_CRITICAL"
    assert asyncio.run(classify("ooda:B")) == "GHOST_ATTACK"
    assert asyncio.run(classify("ooda:C")) == "BENIGN_AUTHORIZED"


def test_replay_falls_back_to_generic_fixture_for_unknown_scenario():
    from backend.config import FIXTURES_DIR
    from backend.llm.replay import ReplayLLM

    llm = ReplayLLM(FIXTURES_DIR)
    import asyncio

    payload, _ = asyncio.run(
        llm.complete_json([{"role": "user", "content": "x"}], task="ooda:D")
    )
    assert payload.get("classification") in {
        "THREAT_CRITICAL",
        "GHOST_ATTACK",
        "BENIGN_AUTHORIZED",
    }


async def test_block_ip_drops_when_evidence_only_has_infrastructure_ips():
    from backend.models import EventSource, EventType, SecurityEvent

    container_ip_event = SecurityEvent(
        source=EventSource.NETWORK,
        type=EventType.SUSPICIOUS_API_REQUEST,
        severity=Severity.CRITICAL,
        summary="probe from the control plane container",
        payload={"ip": "172.19.0.3", "path": "/api/v1/ops/data"},
    )
    payload = {
        "classification": "THREAT_CRITICAL",
        "severity": "critical",
        "confidence": 0.95,
        "actions": [{"action": "block_ip_on_gateway", "target": "172.19.0.3"}],
    }
    mcp = FakeMCP()
    store = ChangeTicketStore(tickets=[])
    agent = OODAAgent(
        StubLLM(payload), policy=PolicyEngine(store), mcp=mcp, change_tickets=store
    )

    incident = await agent.run([container_ip_event], vision(True), now=utc_now())

    assert mcp.calls == []
    assert "never blocked" in incident.decision.reasoning
