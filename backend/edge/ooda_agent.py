"""OODA agent: Observe -> Orient -> Decide -> Act.

The loop is deliberately small and observable:

* **Observe**  collates edge events (USB, network, process) and the vision frame.
* **Orient**   builds a sanitized evidence bundle and checks change tickets.
* **Decide**   asks Muse Glimmer for a structured proposal and validates it.
* **Act**      lets the deterministic policy engine approve/queue actions and
  executes the approved ones through the MCP tool server.

Works identically with mock, replay and live LLM backends.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from ..config import get_settings
from ..llm.base import BaseLLM
from ..models import (
    ActionType,
    Classification,
    EventType,
    Incident,
    IncidentStatus,
    MCPAction,
    MCPActionResult,
    OODADecision,
    PolicyMode,
    SecurityEvent,
    Severity,
    VisionEvidence,
    utc_now,
)
from .mcp_server import MCPToolError
from .policy_engine import ChangeTicketStore, PolicyEngine

OODA_SYSTEM_PROMPT = """You are Meta-Guardian, an autonomous blue-team SOC agent.
Analyse the evidence bundle and reply with STRICT JSON only, no markdown.

Schema:
{
  "classification": "THREAT_CRITICAL" | "GHOST_ATTACK" | "BENIGN_AUTHORIZED" | "BENIGN_UNKNOWN",
  "severity": "info" | "low" | "medium" | "high" | "critical",
  "confidence": 0.0-1.0,
  "reasoning": "short explanation grounded in the evidence",
  "evidence_summary": "one sentence",
  "actions": [
    {"action": "quarantine_usb_file" | "block_ip_on_gateway" | "revoke_session_token" | "kill_process",
     "target": "file name, IP, session token or PID",
     "reason": "why"}
  ]
}

Rules:
- Only propose an action you can justify from the evidence.
- If operator_present is false and a privileged command ran, classify GHOST_ATTACK.
- If change_ticket_valid is true, classify BENIGN_AUTHORIZED and propose no actions.
- Never invent IPs, session tokens or file names; use the ones in the evidence."""

CLASSIFICATION_MAP = {item.value: item for item in Classification}
SEVERITY_MAP = {item.value: item for item in Severity}
ACTION_MAP = {item.value: item for item in ActionType}
MAX_EVIDENCE_EVENTS = 40


def _clamp(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, number))


class OODAAgent:
    def __init__(
        self,
        llm: BaseLLM,
        *,
        policy: PolicyEngine | None = None,
        mcp: Any | None = None,
        change_tickets: ChangeTicketStore | None = None,
    ) -> None:
        self.llm = llm
        self.tickets = change_tickets or (policy.tickets if policy else ChangeTicketStore())
        self.policy = policy or PolicyEngine(self.tickets)
        self.mcp = mcp

    # -- main loop -----------------------------------------------------------

    async def run(
        self,
        events: list[SecurityEvent],
        vision: VisionEvidence | None = None,
        *,
        now: datetime | None = None,
        scenario: str = "unknown",
        incident: Incident | None = None,
    ) -> Incident:
        if not events:
            raise ValueError("OODA requires at least one observed event")

        moment = now or utc_now()
        incident = incident or Incident(scenario="unknown")  # type: ignore[arg-type]
        incident.events = list(events)
        incident.vision = vision

        observe_started = time.perf_counter()

        evidence = self.build_evidence(events, vision, moment)
        observe_ms = round((time.perf_counter() - observe_started) * 1000, 2)

        decision = await self.decide(incident.id, evidence)
        decision.latency_ms = round(decision.latency_ms + observe_ms, 2)

        decision.actions = self.enrich_actions(decision.actions, events, decision)
        policy_outcome = self.policy.evaluate(
            events=events, proposed=decision, vision=vision, now=moment
        )

        results: list[MCPActionResult] = []
        for action in policy_outcome.approved_actions:
            results.append(await self.execute(action))

        incident.decision = decision
        incident.policy = policy_outcome
        incident.action_results = results
        incident.scenario = self._scenario_for(policy_outcome.classification, scenario)
        incident.status = self._status(policy_outcome, results)
        incident.touch()
        return incident

    # -- Observe / Orient ----------------------------------------------------

    def build_evidence(
        self,
        events: list[SecurityEvent],
        vision: VisionEvidence | None,
        moment: datetime,
    ) -> dict[str, Any]:
        operator_present = bool(vision and vision.operator_present)
        presence_known = bool(vision and vision.presence_known)
        ticket = self.tickets.find_covering(moment)
        ticket_valid = bool(ticket and operator_present)

        return {
            "operator_present": operator_present,
            "operator_confidence": vision.confidence if vision else 0.0,
            "vision_summary": vision.description if vision else "no camera evidence",
            "change_ticket_valid": ticket_valid,
            "change_ticket": (
                {
                    "ticket_id": ticket.ticket_id,
                    "operator": ticket.operator,
                    "reason": ticket.reason,
                }
                if ticket and operator_present
                else None
            ),
            "presence_known": presence_known,
            "event_count": len(events),
            "events": [
                self._event_digest(event) for event in events[:MAX_EVIDENCE_EVENTS]
            ],
        }

    @staticmethod
    def _event_digest(event: SecurityEvent) -> dict[str, Any]:
        payload = event.payload or {}
        digest: dict[str, Any] = {
            "type": event.type.value,
            "source": event.source.value,
            "severity": event.severity.value,
            "summary": event.summary[:300],
            "timestamp": event.timestamp.isoformat(),
        }
        for key in ("mountpoint", "ip", "path", "method", "status", "session"):
            if key in payload:
                digest[key] = payload[key]
        findings = payload.get("findings")
        if findings:
            digest["findings"] = [
                {
                    "name": item.get("name"),
                    "sha256": item.get("sha256"),
                    "size": item.get("size"),
                }
                for item in findings[:5]
            ]
        return digest

    # -- Decide --------------------------------------------------------------

    async def decide(
        self, incident_id: str, evidence: dict[str, Any]
    ) -> OODADecision:
        messages = [
            {"role": "system", "content": OODA_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Evidence bundle:\n"
                + json.dumps(evidence, indent=2, ensure_ascii=False),
            },
        ]
        try:
            payload, response = await self.llm.complete_json(messages, task="ooda")
        except Exception as exc:  # noqa: BLE001 - never let the loop crash
            return self._fallback_decision(
                incident_id, f"LLM unavailable: {type(exc).__name__}: {exc}"
            )

        classification = CLASSIFICATION_MAP.get(
            str(payload.get("classification", "")).upper(), Classification.BENIGN_UNKNOWN
        )
        severity = SEVERITY_MAP.get(
            str(payload.get("severity", "")).lower(), Severity.MEDIUM
        )
        actions = self._parse_actions(payload.get("actions"))

        return OODADecision(
            incident_id=incident_id,
            classification=classification,
            severity=severity,
            confidence=_clamp(payload.get("confidence"), 0.0),
            reasoning=str(payload.get("reasoning", ""))[:1200],
            evidence_summary=str(payload.get("evidence_summary", ""))[:600],
            actions=actions,
            model=response.model or get_settings().ooda_model,
            latency_ms=response.latency_ms,
        )

    @staticmethod
    def _parse_actions(raw: Any) -> list[MCPAction]:
        if not isinstance(raw, list):
            return []
        actions: list[MCPAction] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            action_type = ACTION_MAP.get(str(item.get("action", "")).lower())
            if action_type is None:
                continue
            target = str(item.get("target", "")).strip()
            actions.append(
                MCPAction(
                    action=action_type,
                    target=target,
                    reason=str(item.get("reason", ""))[:300],
                )
            )
        return actions

    def _fallback_decision(self, incident_id: str, reason: str) -> OODADecision:
        return OODADecision(
            incident_id=incident_id,
            classification=Classification.BENIGN_UNKNOWN,
            severity=Severity.MEDIUM,
            confidence=0.0,
            reasoning=reason,
            evidence_summary="decision degraded to monitor-only",
            actions=[],
            model="fallback",
        )

    # -- target enrichment ---------------------------------------------------

    def enrich_actions(
        self,
        actions: list[MCPAction],
        events: list[SecurityEvent],
        decision: OODADecision,
    ) -> list[MCPAction]:
        findings: list[tuple[str, str]] = []
        ips: list[str] = []
        sessions: list[str] = []
        mountpoints: list[str] = []

        for event in events:
            payload = event.payload or {}
            if event.type is EventType.USB_INSERTED:
                mountpoint = payload.get("mountpoint")
                if mountpoint:
                    mountpoints.append(str(mountpoint))
                for finding in payload.get("findings") or []:
                    name = finding.get("name")
                    if name:
                        findings.append((str(name), str(mountpoint or "")))
            ip = payload.get("ip")
            if ip and ip not in ("-", "unknown"):
                ips.append(str(ip))
            session = payload.get("session")
            if session and session not in ("-", "unknown"):
                sessions.append(str(session))

        enriched: list[MCPAction] = []
        dropped: list[str] = []

        for action in actions:
            if action.action is ActionType.QUARANTINE_USB_FILE:
                if not findings:
                    dropped.append("quarantine: no suspicious file in evidence")
                    continue
                names = [name for name, _ in findings]
                if action.target not in names:
                    action.target = names[0]
                drive = next(
                    (mount for name, mount in findings if name == action.target),
                    mountpoints[0] if mountpoints else "",
                )
                if drive:
                    action.metadata.setdefault("drive_path", drive)
                elif action.metadata.get("drive_path"):
                    drive = str(action.metadata["drive_path"])
                if not drive:
                    dropped.append("quarantine: no mounted drive path in evidence")
                    continue

            elif action.action is ActionType.BLOCK_IP_ON_GATEWAY:
                if action.target not in ips:
                    if not ips:
                        dropped.append("block_ip: no source IP in evidence")
                        continue
                    action.target = ips[0]

            elif action.action is ActionType.REVOKE_SESSION_TOKEN:
                if action.target not in sessions:
                    if not sessions:
                        dropped.append("revoke: no session token in evidence")
                        continue
                    action.target = sessions[0]

            elif action.action is ActionType.KILL_PROCESS:
                pid = action.metadata.get("pid", action.target)
                try:
                    pid_int = int(pid)
                except (TypeError, ValueError):
                    dropped.append("kill_process: invalid pid")
                    continue
                action.metadata["pid"] = pid_int
                action.target = str(pid_int)

            enriched.append(action)

        if dropped:
            note = "Enrichment dropped: " + "; ".join(dropped)
            decision.reasoning = (decision.reasoning + " | " + note).strip(" |")

        return _dedupe_actions(enriched)

    # -- Act -----------------------------------------------------------------

    async def execute(self, action: MCPAction) -> MCPActionResult:
        if self.mcp is None:
            return MCPActionResult(
                action=action.action,
                target=action.target,
                success=False,
                detail="no MCP executor configured",
            )
        try:
            return await self.mcp.call_tool(
                action.action.value, self._action_arguments(action)
            )
        except MCPToolError as exc:
            return MCPActionResult(
                action=action.action, target=action.target, success=False, detail=str(exc)
            )
        except Exception as exc:  # noqa: BLE001
            return MCPActionResult(
                action=action.action,
                target=action.target,
                success=False,
                detail=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _action_arguments(action: MCPAction) -> dict[str, Any]:
        if action.action is ActionType.QUARANTINE_USB_FILE:
            return {
                "drive_path": str(action.metadata.get("drive_path", "")),
                "filename": action.target,
            }
        if action.action is ActionType.BLOCK_IP_ON_GATEWAY:
            return {"ip": action.target}
        if action.action is ActionType.REVOKE_SESSION_TOKEN:
            return {"session": action.target}
        if action.action is ActionType.KILL_PROCESS:
            return {"pid": int(action.metadata.get("pid", action.target))}
        return {}

    # -- misc ----------------------------------------------------------------

    @staticmethod
    def _scenario_for(classification: Classification, fallback: str) -> str:
        if classification is Classification.GHOST_ATTACK:
            return "B"
        if classification is Classification.BENIGN_AUTHORIZED:
            return "C"
        if classification is Classification.THREAT_CRITICAL:
            return "A"
        return fallback if fallback in ("A", "B", "C") else "unknown"

    @staticmethod
    def _status(
        outcome, results: list[MCPActionResult]
    ) -> IncidentStatus:
        if outcome.mode is PolicyMode.MONITOR and outcome.classification in (
            Classification.BENIGN_AUTHORIZED,
            Classification.BENIGN_UNKNOWN,
        ):
            return IncidentStatus.DISMISSED
        if outcome.pending_actions:
            return IncidentStatus.OPEN
        if results and all(result.success for result in results):
            return IncidentStatus.CONTAINED
        return IncidentStatus.OPEN


def _dedupe_actions(actions: list[MCPAction]) -> list[MCPAction]:
    seen: set[tuple[str, str]] = set()
    unique: list[MCPAction] = []
    for action in actions:
        key = (action.action.value, action.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique


def build_agent(
    llm: BaseLLM,
    *,
    mcp: Any | None = None,
    policy: PolicyEngine | None = None,
    change_tickets: ChangeTicketStore | None = None,
) -> OODAAgent:
    return OODAAgent(llm, policy=policy, mcp=mcp, change_tickets=change_tickets)


__all__ = ["OODAAgent", "build_agent", "OODA_SYSTEM_PROMPT"]
