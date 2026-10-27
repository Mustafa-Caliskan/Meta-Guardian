"""Real MCP tool server for containment actions.

Every tool performs a genuine side effect on the host or on the protected target
service - nothing is simulated:

* ``quarantine_usb_file``  moves a payload out of the drive, makes it read-only
  and writes a SHA-256 receipt.
* ``block_ip_on_gateway``  blocks the source IP on the live FastAPI gateway.
* ``revoke_session_token`` revokes the attacker session on that gateway.
* ``kill_process``         terminates an unauthorized local process via psutil.

The server also speaks a minimal JSON-RPC 2.0 surface (``initialize``,
``tools/list``, ``tools/call``) so it can be mounted behind stdio or HTTP later.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
import psutil

from ..config import get_settings
from ..models import ActionType, MCPActionResult
from .usb_net_watcher import sha256_file

PROTECTED_PIDS = {0, 1, 4}


class MCPToolError(RuntimeError):
    """Validation or execution error for an MCP tool call."""


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": ActionType.QUARANTINE_USB_FILE.value,
        "description": "Move a suspicious file from removable media into the read-only quarantine vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "drive_path": {"type": "string", "description": "Mounted volume root"},
                "filename": {"type": "string", "description": "Relative file name on the volume"},
            },
            "required": ["drive_path", "filename"],
            "additionalProperties": False,
        },
    },
    {
        "name": ActionType.BLOCK_IP_ON_GATEWAY.value,
        "description": "Block a source IP on the protected target service gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 or IPv6 address"}},
            "required": ["ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": ActionType.REVOKE_SESSION_TOKEN.value,
        "description": "Revoke an attacker session token on the target service gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {"session": {"type": "string", "minLength": 3}},
            "required": ["session"],
            "additionalProperties": False,
        },
    },
    {
        "name": ActionType.KILL_PROCESS.value,
        "description": "Terminate an unauthorized local process by PID.",
        "inputSchema": {
            "type": "object",
            "properties": {"pid": {"type": "integer", "minimum": 5}},
            "required": ["pid"],
            "additionalProperties": False,
        },
    },
]


def _split_names(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def _compact_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _require(arguments: dict[str, Any], key: str) -> Any:
    if key not in arguments or arguments[key] in (None, ""):
        raise MCPToolError(f"missing required argument: {key}")
    return arguments[key]


class MCPServer:
    def __init__(
        self,
        *,
        target_base_url: str | None = None,
        quarantine_dir: Path | str | None = None,
        timeout: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        process_factory: Callable[[int], Any] | None = None,
        internal_token: str | None = None,
        allowed_process_names: set[str] | None = None,
    ) -> None:
        settings = get_settings()
        self.target_base_url = (target_base_url or settings.target_base_url).rstrip("/")
        self.quarantine_dir = Path(quarantine_dir or settings.quarantine_dir)
        self.timeout = timeout if timeout is not None else settings.action_timeout
        self.transport = transport
        self._process_factory = process_factory or psutil.Process
        self.internal_token = (
            settings.internal_api_token if internal_token is None else internal_token
        )
        self.allowed_process_names = {
            name.lower()
            for name in (
                allowed_process_names
                if allowed_process_names is not None
                else _split_names(settings.kill_allowlist)
            )
        }

    # -- gateway helpers -----------------------------------------------------

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = (
            {"x-internal-token": self.internal_token} if self.internal_token else None
        )
        try:
            async with httpx.AsyncClient(
                base_url=self.target_base_url,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.post(path, json=payload, headers=headers)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPStatusError as exc:
            raise MCPToolError(
                f"gateway rejected {path}: HTTP {exc.response.status_code} "
                f"{exc.response.text[:160]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise MCPToolError(f"target service unreachable: {exc}") from exc
        if not isinstance(body, dict):
            raise MCPToolError(f"unexpected gateway response: {body!r}")
        return body

    # -- tools ---------------------------------------------------------------

    async def quarantine_usb_file(
        self, drive_path: str, filename: str
    ) -> MCPActionResult:
        action = ActionType.QUARANTINE_USB_FILE
        target = f"{drive_path}/{filename}"
        try:
            drive = Path(drive_path).resolve(strict=True)
            if not drive.is_dir():
                raise MCPToolError(f"drive_path is not a directory: {drive}")
            candidate = (drive / filename).resolve()
            if not candidate.is_relative_to(drive):
                raise MCPToolError("path traversal outside the drive is not allowed")

            self.quarantine_dir.mkdir(parents=True, exist_ok=True)

            if not candidate.exists():
                already = sorted(self.quarantine_dir.glob(f"*__{candidate.name}.quarantine"))
                if already:
                    return MCPActionResult(
                        action=action,
                        target=target,
                        success=True,
                        detail=f"already quarantined at {already[0]}",
                    )
                raise MCPToolError(f"file not found on drive: {candidate}")
            if not candidate.is_file():
                raise MCPToolError(f"not a regular file: {candidate}")

            digest = sha256_file(candidate)
            size = candidate.stat().st_size
            destination = self.quarantine_dir / f"{digest[:16]}__{candidate.name}.quarantine"

            if destination.exists():
                candidate.unlink(missing_ok=True)
            else:
                shutil.move(str(candidate), str(destination))

            self._lock_readonly(destination)
            receipt = destination.with_name(destination.name + ".receipt.json")
            receipt.write_text(
                json.dumps(
                    {
                        "action": action.value,
                        "original_path": str(candidate),
                        "quarantine_path": str(destination),
                        "sha256": digest,
                        "size": size,
                        "quarantined_at": _compact_utc(),
                        "receipt": str(receipt),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return MCPActionResult(
                action=action,
                target=target,
                success=True,
                detail=(
                    f"quarantined {candidate.name} -> {destination} "
                    f"(sha256 {digest[:16]}, {size} bytes, read-only)"
                ),
            )
        except MCPToolError as exc:
            return self._failure(action, target, str(exc))
        except OSError as exc:
            return self._failure(action, target, f"{type(exc).__name__}: {exc}")

    async def block_ip_on_gateway(self, ip: str) -> MCPActionResult:
        action = ActionType.BLOCK_IP_ON_GATEWAY
        try:
            normalized = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return self._failure(action, str(ip), "invalid IP address")

        if ipaddress.ip_address(normalized).is_loopback or ipaddress.ip_address(
            normalized
        ).is_unspecified:
            return self._failure(
                action, normalized, "refusing to block loopback/unspecified address"
            )

        try:
            body = await self._post(
                "/internal/gateway/block_ip",
                {"ip": normalized, "reason": "Meta-Guardian MCP containment"},
            )
        except MCPToolError as exc:
            return self._failure(action, normalized, str(exc))

        return MCPActionResult(
            action=action,
            target=normalized,
            success=bool(body.get("blocked")),
            detail=f"gateway block_list updated for {normalized}",
        )

    async def revoke_session_token(self, session: str) -> MCPActionResult:
        action = ActionType.REVOKE_SESSION_TOKEN
        token = str(session).strip()
        if len(token) < 3 or token == "-":
            return self._failure(action, token, "invalid session token")

        try:
            body = await self._post(
                "/internal/gateway/revoke_session",
                {"session": token, "reason": "Meta-Guardian MCP containment"},
            )
        except MCPToolError as exc:
            return self._failure(action, token, str(exc))

        return MCPActionResult(
            action=action,
            target=token,
            success=bool(body.get("revoked")),
            detail=f"session {token} revoked on gateway",
        )

    async def kill_process(self, pid: int) -> MCPActionResult:
        action = ActionType.KILL_PROCESS
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            return self._failure(action, str(pid), "pid must be an integer")

        protected = set(PROTECTED_PIDS)
        protected.add(os.getpid())
        try:
            protected.add(os.getppid())
        except (AttributeError, OSError):
            pass
        if pid_int in protected or pid_int <= 4:
            return self._failure(action, str(pid_int), "refusing to kill a protected process")

        try:
            process = self._process_factory(pid_int)
            name = process.name()
            if self.allowed_process_names and name.lower() not in self.allowed_process_names:
                return self._failure(
                    action,
                    str(pid_int),
                    f"process {name!r} is not on the kill allowlist",
                )
            process.terminate()
            try:
                process.wait(timeout=3)
            except Exception:  # noqa: BLE001 - wait is best-effort
                pass
        except psutil.NoSuchProcess:
            return self._failure(action, str(pid_int), "process does not exist")
        except psutil.AccessDenied:
            return self._failure(action, str(pid_int), "access denied")
        except Exception as exc:  # noqa: BLE001
            return self._failure(action, str(pid_int), f"{type(exc).__name__}: {exc}")

        return MCPActionResult(
            action=action,
            target=str(pid_int),
            success=True,
            detail=f"terminated {name} (pid {pid_int})",
        )

    # -- MCP surface ---------------------------------------------------------

    @staticmethod
    def list_tools() -> list[dict[str, Any]]:
        return TOOL_SCHEMAS

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> MCPActionResult:
        arguments = dict(arguments or {})

        if name == ActionType.QUARANTINE_USB_FILE.value:
            return await self.quarantine_usb_file(
                _require(arguments, "drive_path"), _require(arguments, "filename")
            )
        if name == ActionType.BLOCK_IP_ON_GATEWAY.value:
            return await self.block_ip_on_gateway(_require(arguments, "ip"))
        if name == ActionType.REVOKE_SESSION_TOKEN.value:
            return await self.revoke_session_token(_require(arguments, "session"))
        if name == ActionType.KILL_PROCESS.value:
            return await self.kill_process(_require(arguments, "pid"))

        raise MCPToolError(f"unknown tool: {name}")

    async def handle_rpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params") or {}

        if method == "initialize":
            result: Any = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "meta-guardian", "version": "0.3.0"},
                "capabilities": {"tools": {"listChanged": False}},
            }
        elif method == "tools/list":
            result = {"tools": self.list_tools()}
        elif method == "tools/call":
            name = params.get("name") or ""
            try:
                outcome = await self.call_tool(name, params.get("arguments") or {})
            except MCPToolError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": str(exc)},
                }
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(outcome.model_dump(mode="json"), ensure_ascii=False),
                    }
                ],
                "isError": not outcome.success,
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }

        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    # -- internal ------------------------------------------------------------

    @staticmethod
    def _failure(action: ActionType, target: str, detail: str) -> MCPActionResult:
        return MCPActionResult(
            action=action, target=target, success=False, detail=detail
        )

    @staticmethod
    def _lock_readonly(path: Path) -> None:
        try:
            os.chmod(path, stat.S_IREAD)
        except OSError:
            pass


__all__ = ["MCPServer", "MCPToolError", "TOOL_SCHEMAS"]
