"""Protected "Aviation Ops API" — the real target service (port 8001).

This is a deliberately small but honest microservice:

* It holds synthetic flight/operations records.
* `/api/v1/ops/data` starts **vulnerable**: no session required, exfiltration
  query allowed, returns HTTP 200.
* After Meta-Guardian applies a deterministic WAF rule it returns 401/403 for
  the same request, which is what the demo verifies live.
* Every request is appended to a JSONL log that the edge watcher tails.
* Gateway state (blocked IPs, revoked sessions, active WAF rule) is exposed on
  `/internal/*` so the MCP tools have something real to act on.

Run standalone:
    python -m backend.target_service
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import get_settings
from .models import WAFRule

settings = get_settings()

DEFAULT_LOG_PATH = Path(
    os.getenv("MG_TARGET_LOG", str(settings.request_log_path))
).resolve()

SUSPICIOUS_MARKERS = (
    "union select",
    "or 1=1",
    "' or '1'='1",
    "; drop",
    "../",
    "xp_cmdshell",
    "<script",
)

EXFIL_MARKERS = ("aircraft=all", "limit=99999", "export=all", "dump=true")


@dataclass
class GatewayState:
    log_path: Path = DEFAULT_LOG_PATH
    blocked_ips: set[str] = field(default_factory=set)
    revoked_sessions: set[str] = field(default_factory=set)
    sessions: dict[str, dict[str, str]] = field(
        default_factory=lambda: {
            "session-ops-valid": {"operator": "ops-engineer", "role": "operator"},
            "session-7f3a9c": {"operator": "ops-admin", "role": "admin"},
        }
    )
    rule: WAFRule | None = None
    revision: int = 0
    rollback_revision: int = 0
    recent: Deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=5000))
    seq: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def reset(self, log_path: Path | None = None) -> None:
        with self.lock:
            self.blocked_ips.clear()
            self.revoked_sessions.clear()
            self.sessions = {
                "session-ops-valid": {"operator": "ops-engineer", "role": "operator"},
                "session-7f3a9c": {"operator": "ops-admin", "role": "admin"},
            }
            self.rule = None
            self.revision = 0
            self.rollback_revision = 0
            self.recent.clear()
            self.seq = 0
            if log_path is not None:
                self.log_path = Path(log_path).resolve()
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self.log_path.write_text("", encoding="utf-8")

    def record(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.seq += 1
            entry["seq"] = self.seq
            self.recent.append(entry)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry


STATE = GatewayState()


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def classify_request(path: str, query: str, token: str | None, state: GatewayState) -> list[str]:
    flags: list[str] = []
    blob = f"{path}?{query}".lower()
    for marker in SUSPICIOUS_MARKERS:
        if marker in blob:
            flags.append(f"sqli_marker:{marker}")
    for marker in EXFIL_MARKERS:
        if marker in blob:
            flags.append(f"exfil_marker:{marker}")
    if path.startswith("/api/v1/admin"):
        flags.append("admin_command")
    if not token and path.startswith("/api/v1/ops/data"):
        flags.append("missing_session")
    if token and token in state.revoked_sessions:
        flags.append("revoked_session")
    return flags


def session_status(token: str | None, *, admin: bool = False) -> tuple[bool, str]:
    if not token:
        return False, "missing_session"
    with STATE.lock:
        if token in STATE.revoked_sessions:
            return False, "revoked_session"
        info = STATE.sessions.get(token)
        if info is None:
            return False, "unknown_session"
        if admin and info.get("role") != "admin":
            return False, "insufficient_role"
    return True, "ok"


def rule_denial(path: str, query: str, token: str | None) -> str | None:
    rule = STATE.rule
    if rule is None:
        return None

    blob = f"{path}?{query}".lower()
    for marker in rule.blocked_markers:
        if marker.lower() in blob:
            return f"waf_blocked_marker:{marker}"

    protected = path.startswith(("/api/v1/ops", "/api/v1/admin"))
    if rule.require_session and protected:
        ok, reason = session_status(token)
        if not ok:
            return f"waf_requires_session:{reason}"
    return None


app = FastAPI(
    title="Aviation Ops API",
    version="1.0.0",
    description="Protected target service used by Meta-Guardian demos.",
)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    started = time.perf_counter()
    ip = request.client.host if request.client else "unknown"
    token = request.headers.get("x-session-token")

    with STATE.lock:
        blocked = ip in STATE.blocked_ips

    if blocked:
        entry = {
            "ts": utc_iso(),
            "ip": ip,
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "status": 403,
            "session": token,
            "flags": ["blocked_ip"],
            "latency_ms": 0.0,
            "denied_by": "gateway_blocklist",
        }
        STATE.record(entry)
        return JSONResponse(
            status_code=403,
            content={"detail": "IP blocked by Meta-Guardian gateway", "request_id": entry["seq"]},
        )

    response = await call_next(request)
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    STATE.record(
        {
            "ts": utc_iso(),
            "ip": ip,
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "status": response.status_code,
            "session": token,
            "flags": classify_request(request.url.path, request.url.query, token, STATE),
            "latency_ms": latency_ms,
            "denied_by": None,
        }
    )
    return response


def _deny(reason: str, status_code: int = 403) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": reason, "blocked": True})


# ---------------------------------------------------------------------------
# Public / operational endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "aviation-ops-api", "revision": STATE.revision}


@app.get("/api/v1/ops/flights")
async def list_flights() -> dict[str, Any]:
    return {
        "flights": [
            {"flight": "PC-1180", "route": "SAW-ADB", "status": "boarding"},
            {"flight": "PC-2214", "route": "SAW-ESB", "status": "on_time"},
            {"flight": "PC-3301", "route": "SAW-TZX", "status": "delayed"},
        ]
    }


@app.get("/api/v1/ops/scan")
async def recon_endpoint() -> dict[str, Any]:
    """Reconnaissance surface, intentionally enumerable in the demo."""
    return {
        "endpoints": [
            "/api/v1/ops/flights",
            "/api/v1/ops/data",
            "/api/v1/admin/command",
        ]
    }


@app.get("/api/v1/ops/data")
async def ops_data(
    aircraft: str = "PC-1180",
    limit: int = 10,
    request: Request = None,  # type: ignore[assignment]
    x_session_token: str | None = Header(default=None),
) -> JSONResponse:
    denial = rule_denial("/api/v1/ops/data", f"aircraft={aircraft}&limit={limit}", x_session_token)
    if denial:
        return _deny(denial)

    records = [
        {
            "aircraft": aircraft,
            "tail": f"TC-{7000 + index}",
            "passenger_manifest_hash": f"sha256:{index:064x}"[:24],
            "crew": 6,
        }
        for index in range(min(max(limit, 1), 50))
    ]
    return JSONResponse(
        status_code=200,
        content={
            "count": len(records),
            "aircraft": aircraft,
            "records": records,
            "leak_surface": "unauthenticated_exfil" if not STATE.rule else "protected",
        },
    )


class AdminCommand(BaseModel):
    command: str = Field(min_length=1, max_length=200)
    target: str = "core-db"


@app.post("/api/v1/admin/command")
async def admin_command(
    payload: AdminCommand,
    x_session_token: str | None = Header(default=None),
) -> JSONResponse:
    denial = rule_denial("/api/v1/admin/command", payload.command, x_session_token)
    if denial:
        return _deny(denial)

    ok, reason = session_status(x_session_token, admin=True)
    if not ok:
        return _deny(reason, status_code=401 if reason != "insufficient_role" else 403)

    return JSONResponse(
        status_code=200,
        content={
            "executed": True,
            "command": payload.command,
            "target": payload.target,
            "operator": STATE.sessions[x_session_token]["operator"],
        },
    )


# ---------------------------------------------------------------------------
# Internal gateway control surface (used by Meta-Guardian MCP tools)
# ---------------------------------------------------------------------------


@app.get("/internal/state")
async def internal_state() -> dict[str, Any]:
    with STATE.lock:
        return {
            "blocked_ips": sorted(STATE.blocked_ips),
            "revoked_sessions": sorted(STATE.revoked_sessions),
            "sessions": sorted(STATE.sessions),
            "revision": STATE.revision,
            "rollback_revision": STATE.rollback_revision,
            "rule": STATE.rule.model_dump() if STATE.rule else None,
            "rule_fingerprint": STATE.rule.fingerprint if STATE.rule else None,
            "requests_total": STATE.seq,
        }


@app.get("/internal/requests")
async def internal_requests(since: int = 0, limit: int = 200) -> dict[str, Any]:
    with STATE.lock:
        entries = [entry for entry in STATE.recent if entry["seq"] > since]
    return {"requests": entries[: max(1, limit)], "last_seq": STATE.seq}


class IPRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    reason: str = ""


@app.post("/internal/gateway/block_ip")
async def block_ip(payload: IPRequest) -> dict[str, Any]:
    with STATE.lock:
        STATE.blocked_ips.add(payload.ip)
    return {"blocked": True, "ip": payload.ip, "reason": payload.reason}


@app.post("/internal/gateway/unblock_ip")
async def unblock_ip(payload: IPRequest) -> dict[str, Any]:
    with STATE.lock:
        STATE.blocked_ips.discard(payload.ip)
    return {"blocked": False, "ip": payload.ip}


class SessionRequest(BaseModel):
    session: str = Field(min_length=3, max_length=128)
    reason: str = ""


@app.post("/internal/gateway/revoke_session")
async def revoke_session(payload: SessionRequest) -> dict[str, Any]:
    with STATE.lock:
        STATE.revoked_sessions.add(payload.session)
        STATE.sessions.pop(payload.session, None)
    return {"revoked": True, "session": payload.session, "reason": payload.reason}


class RuleRequest(BaseModel):
    rule: WAFRule


@app.post("/internal/gateway/apply_rule")
async def apply_rule(payload: RuleRequest) -> dict[str, Any]:
    rule = payload.rule
    if not rule.blocked_markers and not rule.require_session:
        return JSONResponse(
            status_code=422,
            content={"detail": "rule has no effect: add markers or require_session"},
        )

    with STATE.lock:
        STATE.rule = rule
        STATE.revision += 1
        revision = STATE.revision
    return {
        "applied": True,
        "revision": revision,
        "rule_id": rule.rule_id,
        "fingerprint": rule.fingerprint,
    }


@app.post("/internal/gateway/rollback")
async def rollback() -> dict[str, Any]:
    with STATE.lock:
        STATE.rule = None
        STATE.revision += 1
        STATE.rollback_revision = STATE.revision
        revision = STATE.revision
    return {"rolled_back": True, "revision": revision}


@app.post("/internal/reset")
async def reset(log_path: str | None = None) -> dict[str, Any]:
    STATE.reset(Path(log_path) if log_path else None)
    return {"reset": True, "log_path": str(STATE.log_path)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.target_service:app",
        host=settings.host,
        port=settings.target_port,
        reload=False,
    )
