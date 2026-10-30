"""Shared test helpers for Meta-Guardian."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import numpy as np

from backend.llm.base import BaseLLM, LLMResponse
from backend.models import (
    ActionType,
    ChangeTicket,
    EventSource,
    EventType,
    MCPActionResult,
    SecurityEvent,
    Severity,
    VisionEvidence,
    utc_now,
)


def make_frame(width: int = 160, height: int = 120, color: int = 0) -> np.ndarray:
    return np.full((height, width, 3), color, dtype=np.uint8)


def add_rect(
    frame: np.ndarray, x: int, y: int, w: int, h: int, color: int = 255
) -> np.ndarray:
    frame[y : y + h, x : x + w] = color
    return frame


def usb_event(mountpoint: str = "/media/usb", payload_name: str = "payload.ps1") -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        severity=Severity.HIGH,
        summary=f"Removable media mounted at {mountpoint} with 1 suspicious file(s)",
        payload={
            "mountpoint": mountpoint,
            "findings": [
                {
                    "name": payload_name,
                    "sha256": "a" * 64,
                    "size": 128,
                    "path": f"{mountpoint}/{payload_name}",
                }
            ],
            "autorun_executed": False,
        },
    )


def network_event(
    ip: str = "203.0.113.66",
    session: str = "session-7f3a9c",
    session_owner: str = "ops-admin",
    session_role: str = "admin",
    session_origin_ip: str = "10.0.0.31",
) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.NETWORK,
        type=EventType.SUSPICIOUS_API_REQUEST,
        severity=Severity.CRITICAL,
        summary=f"GET /api/v1/ops/data from {ip} -> HTTP 200",
        payload={
            "ip": ip,
            "session": session,
            "session_owner": session_owner,
            "session_role": session_role,
            "session_origin_ip": session_origin_ip,
            "method": "GET",
            "path": "/api/v1/ops/data",
            "status": 200,
        },
    )


def admin_event(
    ip: str = "203.0.113.66",
    session: str = "session-7f3a9c",
    session_owner: str = "ops-admin",
    session_role: str = "admin",
    session_origin_ip: str = "10.0.0.31",
) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.NETWORK,
        type=EventType.ADMIN_COMMAND,
        severity=Severity.HIGH,
        summary=f"POST /api/v1/admin/command from {ip}",
        payload={
            "ip": ip,
            "session": session,
            "session_owner": session_owner,
            "session_role": session_role,
            "session_origin_ip": session_origin_ip,
            "method": "POST",
            "status": 200,
        },
    )


def vision(present: bool = True, confidence: float = 0.92) -> VisionEvidence:
    return VisionEvidence(
        operator_present=present,
        confidence=confidence,
        roi=[10, 10, 40, 40],
        description="operator at the console" if present else "empty seat",
    )


def covering_ticket(operator: str = "ops-admin", ticket_id: str = "CHG-2026-77") -> ChangeTicket:
    now = utc_now()
    return ChangeTicket(
        ticket_id=ticket_id,
        operator=operator,
        reason="approved maintenance window",
        window_start=now - timedelta(minutes=30),
        window_end=now + timedelta(minutes=30),
        usb_allowed=True,
    )


class FakeMCP:
    def __init__(self, success: bool = True, fail_names: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.success = success
        self.fail_names = fail_names or set()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> MCPActionResult:
        self.calls.append((name, arguments))
        target = str(
            arguments.get("filename")
            or arguments.get("ip")
            or arguments.get("session")
            or arguments.get("pid")
            or "?"
        )
        ok = self.success and name not in self.fail_names
        return MCPActionResult(
            action=ActionType(name), target=target, success=ok, detail="fake"
        )


class StubLLM(BaseLLM):
    name = "stub"

    def __init__(self, payload: dict[str, Any] | None = None, *, error: Exception | None = None):
        self.payload = payload
        self.error = error
        self.calls = 0

    async def complete(
        self,
        messages,
        *,
        task: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        import json

        self.calls += 1
        if self.error:
            raise self.error
        return LLMResponse(
            text=json.dumps(self.payload or {}),
            model="stub-model",
            latency_ms=1.5,
        )
