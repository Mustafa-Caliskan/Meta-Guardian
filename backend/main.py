"""Meta-Guardian control center: FastAPI app + WebSocket SOC stream (port 8000).

This is the MVP glue for Day 4. It wires the real pipeline together and serves
the dark SOC cockpit in ``frontend/``:

* edge watchers  -> EventBus -> WebSocket
* OODA agent     -> policy engine -> MCP tools -> Incident store
* gateway status -> proxied from the protected target service (port 8001)
* evidence       -> captured frame + SAM mask served for the cockpit

No Streamlit, no build step: plain FastAPI + vanilla JS.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from collections import deque
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, Deque

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import PROJECT_ROOT, SCENARIOS_DIR, Settings, get_settings
from .edge.mcp_server import MCPServer
from .edge.ooda_agent import OODAAgent
from .edge.policy_engine import ChangeTicketStore, PolicyEngine
from .edge.usb_net_watcher import EventBus, NetWatcher, USBWatcher
from .llm.factory import build_llm
from .models import (
    ChangeTicket,
    Classification,
    EventSource,
    EventType,
    Incident,
    IncidentStatus,
    MCPActionResult,
    PolicyMode,
    SecurityEvent,
    Severity,
    VisionEvidence,
    utc_now,
)
from .vision import SAMBridge, capture_frame

FRONTEND_DIR = PROJECT_ROOT / "frontend"
MAX_EVENT_HISTORY = 500


class ConnectionManager:
    """Tracks WebSocket clients and fans out JSON messages."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, default=str)
        async with self._lock:
            targets = list(self._clients)
        stale: list[WebSocket] = []
        for client in targets:
            try:
                await client.send_text(payload)
            except Exception:  # noqa: BLE001 - client vanished mid-send
                stale.append(client)
        if stale:
            async with self._lock:
                for client in stale:
                    self._clients.discard(client)


class SimulateRequest(BaseModel):
    scenario: str = Field(default="A", pattern="^[ABC]$")


class AppState:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        mcp: Any | None = None,
        enable_watchers: bool = False,
        runtime_dir: Path | None = None,
        scenarios_dir: Path | None = None,
        frame_provider: Any | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.enable_watchers = enable_watchers
        self.runtime_dir = Path(runtime_dir or self.settings.runtime_dir)
        self.scenarios_dir = Path(scenarios_dir or SCENARIOS_DIR)
        self.frame_provider = frame_provider
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

        self.bus = EventBus(history_size=MAX_EVENT_HISTORY)
        self.connections = ConnectionManager()
        self.events: Deque[SecurityEvent] = deque(maxlen=MAX_EVENT_HISTORY)
        self.incidents: dict[str, Incident] = {}
        self.incident_order: Deque[str] = deque(maxlen=200)

        self.tickets = ChangeTicketStore()
        self.policy = PolicyEngine(self.tickets)
        self.mcp = mcp if mcp is not None else MCPServer()
        self.agent = OODAAgent(
            build_llm(self.settings),
            policy=self.policy,
            mcp=self.mcp,
            change_tickets=self.tickets,
        )
        self.sam = SAMBridge()

        self.usb_watcher = USBWatcher(self.bus)
        self.net_watcher = NetWatcher(self.bus, self.settings.request_log_path)
        self._tasks: list[asyncio.Task] = []
        self._bus_subscribed = False

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        if not self._bus_subscribed:
            self.bus.subscribe(self._on_event)
            self._bus_subscribed = True
        if self.enable_watchers:
            await self.usb_watcher.start()
            await self.net_watcher.start()
            self._tasks = [t for t in (self.usb_watcher._task, self.net_watcher._task) if t]

    async def stop(self) -> None:
        await self.usb_watcher.stop()
        await self.net_watcher.stop()
        for task in self._tasks:
            task.cancel()
        self._tasks = []

    # -- bus -> websocket ----------------------------------------------------

    async def _on_event(self, event: SecurityEvent) -> None:
        self.events.append(event)
        await self.connections.broadcast(
            {"type": "event", "event": event.model_dump(mode="json")}
        )

    async def publish(self, event: SecurityEvent) -> None:
        await self.bus.publish(event)

    async def publish_incident(self, incident: Incident) -> None:
        await self.connections.broadcast(
            {"type": "incident", "incident": incident.model_dump(mode="json")}
        )
        await self.connections.broadcast({"type": "state", "state": self.snapshot()})

    # -- snapshot / health ---------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        incidents = [self.incidents[i] for i in self.incident_order if i in self.incidents]
        latest = incidents[-1] if incidents else None
        return {
            "mode": self.settings.mode.value,
            "watchers_enabled": self.enable_watchers,
            "clients": self.connections.count,
            "counts": {
                "events": len(self.events),
                "incidents": len(incidents),
                "contained": sum(
                    1 for inc in incidents if inc.status is IncidentStatus.CONTAINED
                ),
                "pending_approval": sum(
                    1
                    for inc in incidents
                    if inc.policy and inc.policy.mode is PolicyMode.APPROVAL
                ),
            },
            "models": {
                "ooda": self.settings.ooda_model,
                "forensics": self.settings.forensics_model,
                "sam": self.settings.sam_model,
                "spark_open": self.settings.spark_open_model,
                "mode": self.settings.mode.value,
            },
            "latest_incident": latest.model_dump(mode="json") if latest else None,
        }

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return [event.model_dump(mode="json") for event in list(self.events)[-limit:]]

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        items = [self.incidents[i] for i in self.incident_order if i in self.incidents]
        return [item.model_dump(mode="json") for item in items[-limit:]][::-1]

    # -- evidence paths ------------------------------------------------------

    def evidence_dir(self, incident_id: str) -> Path:
        return self.runtime_dir / "evidence" / incident_id

    def frame_path(self, incident_id: str) -> Path | None:
        incident = self.incidents.get(incident_id)
        if incident and incident.vision and incident.vision.frame_path:
            path = Path(incident.vision.frame_path)
            return path if path.exists() else None
        candidate = self.evidence_dir(incident_id) / "frame.png"
        return candidate if candidate.exists() else None

    def mask_path(self, incident_id: str) -> Path | None:
        incident = self.incidents.get(incident_id)
        if incident and incident.vision and incident.vision.mask_path:
            path = Path(incident.vision.mask_path)
            return path if path.exists() else None
        candidate = self.evidence_dir(incident_id) / "mask.png"
        return candidate if candidate.exists() else None

    # -- scenarios -----------------------------------------------------------

    async def simulate(self, scenario: str) -> Incident:
        scenario = scenario.upper()
        if scenario not in ("A", "B", "C"):
            raise HTTPException(status_code=422, detail="scenario must be A, B or C")

        sandbox = self.runtime_dir / "sim_usb"
        incident = Incident(scenario=scenario)  # type: ignore[arg-type]
        evidence = self.evidence_dir(incident.id)
        evidence.mkdir(parents=True, exist_ok=True)

        ticket_added: ChangeTicket | None = None
        try:
            if scenario == "A":
                usb_root = self._prepare_usb_sandbox(sandbox)
                events = [self._usb_event(usb_root), self._network_event()]
                vision = self._vision(incident.id, operator_present=True)
            elif scenario == "B":
                events = [self._admin_event()]
                vision = self._vision(incident.id, operator_present=False)
            else:
                ticket_added = self._temporary_ticket()
                events = [self._usb_event(self._prepare_usb_sandbox(sandbox)), self._network_event()]
                vision = self._vision(incident.id, operator_present=True)

            for event in events:
                await self.publish(event)

            incident = await self.agent.run(
                events, vision, now=utc_now(), scenario=scenario, incident=incident
            )
            self._remember(incident)
            await self.publish_incident(incident)
            return incident
        finally:
            if ticket_added is not None:
                self.tickets.replace(
                    [t for t in self.tickets.tickets if t.ticket_id != ticket_added.ticket_id]
                )

    def _prepare_usb_sandbox(self, sandbox: Path) -> Path:
        if sandbox.exists():
            shutil.rmtree(sandbox, ignore_errors=True)
        sandbox.mkdir(parents=True, exist_ok=True)
        (sandbox / "payload.ps1").write_text(
            "# simulated rogue payload, quarantined by Meta-Guardian\n"
            "Write-Host 'Meta-Guardian demo payload'\n",
            encoding="utf-8",
        )
        return sandbox

    def _usb_event(self, mountpoint: Path) -> SecurityEvent:
        payload_file = mountpoint / "payload.ps1"
        return SecurityEvent(
            source=EventSource.USB,
            type=EventType.USB_INSERTED,
            severity=Severity.HIGH,
            summary=f"Removable media mounted at {mountpoint} with 1 suspicious file(s)",
            payload={
                "mountpoint": str(mountpoint),
                "device": "SIM-USB",
                "findings": [
                    {
                        "name": payload_file.name,
                        "path": str(payload_file),
                        "size": payload_file.stat().st_size,
                        "sha256": "0" * 64,
                        "extension": ".ps1",
                    }
                ],
                "autorun_executed": False,
            },
        )

    @staticmethod
    def _network_event() -> SecurityEvent:
        return SecurityEvent(
            source=EventSource.NETWORK,
            type=EventType.SUSPICIOUS_API_REQUEST,
            severity=Severity.CRITICAL,
            summary="GET /api/v1/ops/data?aircraft=ALL from 203.0.113.66 -> HTTP 200",
            payload={
                "ip": "203.0.113.66",
                "session": "session-7f3a9c",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL&limit=99999",
                "status": 200,
            },
        )

    @staticmethod
    def _admin_event() -> SecurityEvent:
        return SecurityEvent(
            source=EventSource.NETWORK,
            type=EventType.ADMIN_COMMAND,
            severity=Severity.HIGH,
            summary="POST /api/v1/admin/command from 203.0.113.66 with no operator on camera",
            payload={
                "ip": "203.0.113.66",
                "session": "session-7f3a9c",
                "method": "POST",
                "path": "/api/v1/admin/command",
                "status": 200,
            },
        )

    def _vision(self, incident_id: str, *, operator_present: bool) -> VisionEvidence:
        target_dir = self.evidence_dir(incident_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        frame_path = target_dir / "frame.png"
        mask_path = target_dir / "mask.png"

        fallback_name = "operator_present.png" if operator_present else "operator_absent.png"
        try:
            captured = capture_frame(
                frame_path,
                fallback_dir=self.scenarios_dir,
                fallback_name=fallback_name,
                warmup_frames=1,
                provider=self.frame_provider,
            )
            detail = captured.detail
        except Exception as exc:  # noqa: BLE001 - cockpit must still work
            detail = f"frame unavailable: {type(exc).__name__}: {exc}"
            self._log_vision_error(incident_id, "frame", exc)

        roi = [40, 30, 60, 70] if operator_present else [0, 0, 1, 1]
        try:
            self.sam._write_mask(mask_path, _blank_frame(), roi=roi)
        except Exception as exc:  # noqa: BLE001
            detail += f"; mask unavailable: {type(exc).__name__}: {exc}"
            self._log_vision_error(incident_id, "mask", exc)

        return VisionEvidence(
            operator_present=operator_present,
            confidence=0.94 if operator_present else 0.88,
            roi=roi,
            description=(
                "operator at the console"
                if operator_present
                else "empty seat while a privileged command ran"
            ),
            frame_path=str(frame_path) if frame_path.exists() else None,
            mask_path=str(mask_path) if mask_path.exists() else None,
            model=self.settings.sam_model,
        )

    def _log_vision_error(self, incident_id: str, stage: str, exc: Exception) -> None:
        import traceback

        try:
            path = self.runtime_dir / "vision_errors.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"[{utc_now().isoformat()}] {incident_id} {stage}: {exc!r}\n")
                handle.write(traceback.format_exc() + "\n")
        except OSError:
            pass

    def _temporary_ticket(self) -> ChangeTicket:
        now = utc_now()
        ticket = ChangeTicket(
            ticket_id=f"CHG-SIM-{now.strftime('%H%M%S')}",
            operator="mustafa",
            reason="approved maintenance window (simulated)",
            window_start=now - timedelta(minutes=10),
            window_end=now + timedelta(minutes=10),
            usb_allowed=True,
        )
        self.tickets.add(ticket)
        return ticket

    def _remember(self, incident: Incident) -> None:
        self.incidents[incident.id] = incident
        self.incident_order.append(incident.id)

    # -- approvals -----------------------------------------------------------

    async def approve(self, incident_id: str) -> Incident:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        if incident.policy is None or incident.policy.mode is not PolicyMode.APPROVAL:
            raise HTTPException(status_code=409, detail="incident has no pending approval")

        pending = list(incident.policy.pending_actions)
        approved: list = []
        limited: list = []
        for action in pending:
            if self.policy.rate_limiter.allow(action.action.value):
                approved.append(action)
            else:
                limited.append(action)

        results: list[MCPActionResult] = []
        for action in approved:
            results.append(await self.agent.execute(action))

        incident.action_results.extend(results)
        incident.policy.approved_actions.extend(approved)
        incident.policy.rate_limited_actions.extend(limited)
        incident.policy.pending_actions = []
        incident.policy.mode = PolicyMode.AUTO
        incident.policy.reason += " | approved by human operator"
        success = bool(results) and all(result.success for result in results)
        incident.status = IncidentStatus.CONTAINED if success else IncidentStatus.OPEN
        incident.touch()

        await self.publish_incident(incident)
        return incident

    async def dismiss(self, incident_id: str) -> Incident:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        incident.status = IncidentStatus.DISMISSED
        incident.touch()
        await self.publish_incident(incident)
        return incident

    # -- gateway proxy -------------------------------------------------------

    async def gateway_status(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                base_url=self.settings.target_base_url, timeout=3.0
            ) as client:
                state = await client.get("/internal/state")
                state.raise_for_status()
                health = await client.get("/health")
                body = state.json()
                body["reachable"] = True
                body["health"] = health.json() if health.status_code == 200 else {}
                return body
        except Exception as exc:  # noqa: BLE001 - cockpit shows degraded state
            return {
                "reachable": False,
                "error": f"{type(exc).__name__}: {exc}",
                "blocked_ips": [],
                "revoked_sessions": [],
                "rule": None,
                "revision": 0,
            }


def _blank_frame():  # pragma: no cover - trivial helper for mask generation
    import numpy as np

    return np.zeros((120, 160, 3), dtype=np.uint8)


def create_app(
    state: AppState | None = None,
    *,
    enable_watchers: bool | None = None,
) -> FastAPI:
    if state is None:
        state = AppState(
            enable_watchers=bool(enable_watchers) if enable_watchers is not None else False
        )
    elif enable_watchers is not None:
        state.enable_watchers = enable_watchers

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await state.start()
        try:
            yield
        finally:
            await state.stop()

    app = FastAPI(
        title="Meta-Guardian Control Center",
        version="0.4.0",
        description="Autonomous cyber-physical SOC control plane.",
        lifespan=lifespan,
    )
    app.state.mg = state

    # ------------------------------------------------------------------ HTTP

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "meta-guardian-control-center",
            "mode": state.settings.mode.value,
            "watchers_enabled": state.enable_watchers,
            "clients": state.connections.count,
        }

    @app.get("/api/config")
    async def config() -> dict[str, Any]:
        return {
            "mode": state.settings.mode.value,
            "models": {
                "ooda": state.settings.ooda_model,
                "forensics": state.settings.forensics_model,
                "sam": state.settings.sam_model,
                "spark_open": state.settings.spark_open_model,
            },
            "target": state.settings.target_base_url,
            "confidence_bands": {
                "auto": state.policy.min_auto_confidence,
                "approval": state.policy.min_approval_confidence,
            },
            "rate_limit": {
                "max_actions_per_minute": state.policy.rate_limiter.max_events,
                "window_seconds": state.policy.rate_limiter.window_seconds,
            },
        }

    @app.get("/api/state")
    async def snapshot() -> dict[str, Any]:
        return state.snapshot()

    @app.get("/api/events")
    async def events(limit: int = 100) -> dict[str, Any]:
        return {"events": state.recent_events(max(1, min(limit, MAX_EVENT_HISTORY)))}

    @app.get("/api/incidents")
    async def incidents(limit: int = 50) -> dict[str, Any]:
        return {"incidents": state.list_incidents(max(1, min(limit, 200)))}

    @app.get("/api/incidents/{incident_id}")
    async def incident_detail(incident_id: str) -> dict[str, Any]:
        incident = state.incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident.model_dump(mode="json")

    @app.get("/api/incidents/{incident_id}/frame")
    async def incident_frame(incident_id: str):
        path = state.frame_path(incident_id)
        if path is None:
            raise HTTPException(status_code=404, detail="frame not available")
        return FileResponse(path, media_type="image/png")

    @app.get("/api/incidents/{incident_id}/mask")
    async def incident_mask(incident_id: str):
        path = state.mask_path(incident_id)
        if path is None:
            raise HTTPException(status_code=404, detail="mask not available")
        return FileResponse(path, media_type="image/png")

    @app.post("/api/simulate")
    async def simulate(request: SimulateRequest) -> dict[str, Any]:
        incident = await state.simulate(request.scenario)
        return incident.model_dump(mode="json")

    @app.post("/api/incidents/{incident_id}/approve")
    async def approve(incident_id: str) -> dict[str, Any]:
        incident = await state.approve(incident_id)
        return incident.model_dump(mode="json")

    @app.post("/api/incidents/{incident_id}/dismiss")
    async def dismiss(incident_id: str) -> dict[str, Any]:
        incident = await state.dismiss(incident_id)
        return incident.model_dump(mode="json")

    @app.get("/api/gateway")
    async def gateway() -> dict[str, Any]:
        return await state.gateway_status()

    @app.get("/api/scenarios")
    async def scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {
                    "id": "A",
                    "title": "Rogue USB + API exfiltration",
                    "detail": "Unsigned payload at rest plus HTTP 200 mass exfiltration.",
                },
                {
                    "id": "B",
                    "title": "Ghost attack",
                    "detail": "Privileged command while no operator is visible.",
                },
                {
                    "id": "C",
                    "title": "Authorized maintenance",
                    "detail": "Valid change ticket and operator present: no false alarm.",
                },
            ]
        }

    # -------------------------------------------------------------- WebSocket

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await state.connections.connect(websocket)
        try:
            await websocket.send_json(
                {
                    "type": "hello",
                    "state": state.snapshot(),
                    "events": state.recent_events(50),
                }
            )
            while True:
                message = await websocket.receive_text()
                if message.strip() == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001 - never crash the server on a bad client
            pass
        finally:
            await state.connections.disconnect(websocket)

    # --------------------------------------------------------------- frontend

    if FRONTEND_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

        @app.get("/")
        async def index():
            return FileResponse(FRONTEND_DIR / "index.html")

    return app


app = create_app(enable_watchers=True)


def main() -> None:  # pragma: no cover - manual entrypoint
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "backend.main:app", host=settings.host, port=settings.port, reload=False
    )


if __name__ == "__main__":  # pragma: no cover
    main()
