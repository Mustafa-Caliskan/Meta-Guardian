"""Deterministic offline LLM used when LLM_MODE=mock (no keys, no network)."""

from __future__ import annotations

import json
import time
from datetime import timedelta

from .base import BaseLLM, LLMResponse, Message
from ..models import utc_now


class MockLLM(BaseLLM):
    name = "mock"

    async def complete(
        self,
        messages: list[Message],
        *,
        task: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        started = time.perf_counter()
        prompt = " ".join(m.get("content", "") for m in messages).lower()
        payload = self._payload(task or self._infer_task(prompt), prompt)
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        return LLMResponse(
            text=text,
            model=model or f"mock-{task or 'general'}",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    @staticmethod
    def _infer_task(prompt: str) -> str:
        if "patch" in prompt or "waf" in prompt:
            return "patch"
        if "forensic" in prompt or "siem" in prompt or "attack chain" in prompt:
            return "forensics"
        return "ooda"

    def _payload(self, task: str, prompt: str) -> dict:
        if task.startswith("forensics"):
            return self._forensics()
        if task.startswith("patch"):
            return self._patch()
        return self._ooda(prompt)

    @staticmethod
    def _ooda(prompt: str) -> dict:
        compact = prompt.replace(" ", "")
        if '"change_ticket_valid":true' in compact:
            classification = "BENIGN_AUTHORIZED"
            reasoning = "Change ticket covers the event window and an operator is present."
        elif (
            '"session_origin_scope":"remote"' in compact
            and '"operator_present":true' in compact
            and "admin_command" in compact
        ):
            classification = "CREDENTIAL_MISUSE"
            reasoning = (
                "Privileged admin command arrived from a remote origin while an "
                "operator is physically at the console: the token is being used "
                "from somewhere the operator is not."
            )
        elif (
            '"operator_present":false' in compact
            and "admin_command" in compact
        ):
            classification = "GHOST_ATTACK"
            reasoning = "Critical admin action executed while no authorized operator was visible."
        else:
            classification = "THREAT_CRITICAL"
            reasoning = "Unknown USB payload combined with data exfiltration attempt."

        actions = []
        if classification in ("THREAT_CRITICAL", "GHOST_ATTACK"):
            actions = [
                {
                    "action": "quarantine_usb_file",
                    "target": "payload.ps1",
                    "reason": "Unsigned PowerShell script found at rest on removable media.",
                },
                {
                    "action": "block_ip_on_gateway",
                    "target": "203.0.113.66",
                    "reason": "Source IP of the data exfiltration request.",
                },
                {
                    "action": "revoke_session_token",
                    "target": "session-7f3a9c",
                    "reason": "Session used by the remote attacker.",
                },
            ]
        elif classification == "CREDENTIAL_MISUSE":
            actions = [
                {
                    "action": "block_ip_on_gateway",
                    "target": "203.0.113.66",
                    "reason": "Remote origin using a privileged session.",
                },
                {
                    "action": "revoke_session_token",
                    "target": "session-7f3a9c",
                    "reason": "Hijacked admin session should be revoked.",
                },
            ]

        return {
            "classification": classification,
            "severity": "critical" if classification != "BENIGN_AUTHORIZED" else "low",
            "confidence": 0.72 if classification == "CREDENTIAL_MISUSE" else 0.93,
            "reasoning": reasoning,
            "evidence_summary": "Correlated USB insertion, suspicious API request and camera frame.",
            "actions": actions,
        }

    @staticmethod
    def _forensics() -> dict:
        discovered = utc_now() - timedelta(days=3)
        return {
            "attack_chain": [
                {
                    "timestamp": discovered.isoformat(),
                    "source_ip": "203.0.113.66",
                    "endpoint": "/api/v1/ops/scan",
                    "description": "Port and endpoint enumeration three days before the incident.",
                },
                {
                    "timestamp": (discovered + timedelta(days=3)).isoformat(),
                    "source_ip": "203.0.113.66",
                    "endpoint": "/api/v1/ops/data?aircraft=ALL",
                    "description": "Unauthenticated data exfiltration returning HTTP 200.",
                },
            ],
            "earliest_discovery": discovered.isoformat(),
            "vulnerable_file": "backend/target_service.py",
            "vulnerable_line": 1,
            "vulnerable_code": "missing authorization check on /ops/data",
            "summary": "Reconnaissance three days earlier led to an unauthenticated data leak.",
            "citations": [
                {
                    "log_file": "data/history_logs/siem_30d.log",
                    "line": 42,
                    "excerpt": "GET /api/v1/ops/scan 203.0.113.66 404",
                }
            ],
        }

    @staticmethod
    def _patch() -> dict:
        return {
            "target_file": "backend/target_service.py",
            "rule_id": "MG-WAF-001",
            "rationale": "Require a valid session token and block known exfiltration patterns.",
            "patch_code": (
                "def authorize(request):\n"
                "    token = request.headers.get('x-session-token', '')\n"
                "    return token in ACTIVE_SESSIONS\n"
            ),
            "blocked_markers": ["union select", "../", "; drop"],
        }
