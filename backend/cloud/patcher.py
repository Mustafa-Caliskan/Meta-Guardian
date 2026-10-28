"""Live auto-patch: orchestration, not code generation.

The LLM chooses *which pre-approved template* to apply and why. It never emits
executable code. The patcher then:

1. builds a deterministic ``WAFRule`` (allowlisted markers + session requirement),
2. hot-loads it into the target service,
3. replays the exact attack that previously returned ``HTTP 200``,
4. verifies it now returns ``HTTP 403`` (or 401),
5. rolls back automatically if verification fails.

That ``200 -> 403`` transition is the demo's strongest evidence, and every step
is recorded in ``PatchResult`` with a stable rule fingerprint.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from ..config import get_settings
from ..models import (
    ForensicsReport,
    Incident,
    PatchResult,
    WAFRule,
    utc_now,
)

EXFIL_PATH = "/api/v1/ops/data"
EXFIL_PARAMS = {"aircraft": "ALL", "limit": 99999}

# Deterministic, allowlisted markers. The LLM may select from these but cannot
# invent new ones; new markers require a code change and a review.
APPROVED_MARKERS = {
    "mass_exfiltration": ["aircraft=all", "limit=99999", "export=all", "dump=true"],
    "path_traversal": ["../", "..\\"],
    "sqli": ["union select", "' or '1'='1", "; drop"],
    "script_injection": ["<script", "javascript:"],
}

TEMPLATE_CHOICES = ("require_session", "block_markers", "both")


@dataclass
class AttackProbe:
    status: int
    body: str = ""
    latency_ms: float = 0.0


async def default_attack(
    base_url: str,
    *,
    headers: dict[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
) -> AttackProbe:
    started = time.perf_counter()
    request_headers = {"x-mg-probe": "1"}
    if headers:
        request_headers.update(headers)
    async with httpx.AsyncClient(
        base_url=base_url, timeout=timeout, transport=transport
    ) as client:
        response = await client.get(
            EXFIL_PATH, params=EXFIL_PARAMS, headers=request_headers
        )
        return AttackProbe(
            status=response.status_code,
            body=response.text[:400],
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )


def choose_markers(report: ForensicsReport | None, events: Any = None) -> list[str]:
    """Pick allowlisted markers based on the observed evidence."""
    markers: list[str] = []
    text = " ".join(
        part
        for part in [
            (report.summary if report else ""),
            (report.vulnerable_code if report else "") or "",
        ]
    ).lower()

    if any(token in text for token in ("exfil", "aircraft", "mass", "dump", "export")):
        markers.extend(APPROVED_MARKERS["mass_exfiltration"])
    if "traversal" in text or "../" in text:
        markers.extend(APPROVED_MARKERS["path_traversal"])
    if "sql" in text or "union" in text:
        markers.extend(APPROVED_MARKERS["sqli"])

    if not markers:
        markers.extend(APPROVED_MARKERS["mass_exfiltration"])

    deduped: list[str] = []
    for marker in markers:
        if marker not in deduped:
            deduped.append(marker)
    return deduped[:6]


class Patcher:
    def __init__(
        self,
        *,
        target_base_url: str | None = None,
        internal_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float | None = None,
        attack: Callable[..., Awaitable[AttackProbe]] | None = None,
    ) -> None:
        settings = get_settings()
        self.target_base_url = (target_base_url or settings.target_base_url).rstrip("/")
        self.internal_token = (
            settings.internal_api_token if internal_token is None else internal_token
        )
        self.transport = transport
        self.timeout = timeout if timeout is not None else settings.action_timeout
        self.attack = attack or default_attack

    def _headers(self) -> dict[str, str] | None:
        return {"x-internal-token": self.internal_token} if self.internal_token else None

    async def _control(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=self.target_base_url,
            timeout=self.timeout,
            transport=self.transport,
        ) as client:
            response = await client.post(path, json=payload, headers=self._headers())
            response.raise_for_status()
            body = response.json()
        if not isinstance(body, dict):
            raise ValueError(f"unexpected gateway response: {body!r}")
        return body

    def build_rule(
        self, incident: Incident, report: ForensicsReport | None
    ) -> WAFRule:
        return WAFRule(
            rule_id=f"MG-WAF-{incident.id[-6:].upper()}",
            blocked_markers=choose_markers(report, incident.events),
            require_session=True,
            require_operator=False,
            rationale=(
                "Deterministic rule selected after forensics: require a valid "
                "session on ops endpoints and block known exfiltration markers."
            ),
        )

    async def patch(
        self,
        incident: Incident,
        report: ForensicsReport | None = None,
        *,
        rule: WAFRule | None = None,
    ) -> PatchResult:
        started = time.perf_counter()
        rule = rule or self.build_rule(incident, report)
        result = PatchResult(
            incident_id=incident.id,
            target_file=(report.vulnerable_file if report else None)
            or "backend/target_service.py",
            rule_id=rule.rule_id,
            rule_fingerprint=rule.fingerprint,
            rationale=rule.rationale,
            patch_code=(
                "template=require_session+block_markers; "
                f"markers={','.join(rule.blocked_markers)}"
            ),
            model=(report.model if report else None) or get_settings().code_model,
        )

        try:
            before = await self.attack(self.target_base_url, transport=self.transport)
        except Exception as exc:  # noqa: BLE001
            result.before_status = None
            result.verification_note = f"before probe failed: {type(exc).__name__}: {exc}"
            result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return result

        result.before_status = before.status

        try:
            applied = await self._control(
                "/internal/gateway/apply_rule", {"rule": rule.model_dump()}
            )
            result.applied = bool(applied.get("applied"))
        except Exception as exc:  # noqa: BLE001
            result.verification_note = f"apply failed: {type(exc).__name__}: {exc}"
            result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return result

        try:
            after = await self.attack(self.target_base_url, transport=self.transport)
            result.after_status = after.status
        except Exception as exc:  # noqa: BLE001
            result.verification_note = f"after probe failed: {type(exc).__name__}: {exc}"
            await self._rollback_safely(result)
            result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return result

        result.mark_verified(before.status, after.status)
        if not result.verified:
            await self._rollback_safely(result)

        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return result

    async def _rollback_safely(self, result: PatchResult) -> None:
        try:
            await self._control("/internal/gateway/rollback", {})
            result.rolled_back = True
            result.verification_note += " | rolled back"
        except Exception as exc:  # noqa: BLE001
            result.verification_note += f" | rollback failed: {type(exc).__name__}"


__all__ = [
    "APPROVED_MARKERS",
    "AttackProbe",
    "Patcher",
    "TEMPLATE_CHOICES",
    "choose_markers",
    "default_attack",
]
