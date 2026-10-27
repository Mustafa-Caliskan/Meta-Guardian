"""Edge watchers: real removable-media detection and target-API log tailing.

Both watchers are deliberately dependency-light and testable:

* ``USBWatcher.poll_once()`` is synchronous and accepts an injectable partition
  provider, so tests never need a real USB stick.
* ``NetWatcher.poll_once()`` reads the target service JSONL log incrementally
  and survives truncation/rotation.

In production each watcher runs as an asyncio task and publishes
``SecurityEvent`` objects to the shared ``EventBus``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Iterable, Protocol

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard dependency at runtime
    psutil = None  # type: ignore[assignment]

from ..config import get_settings
from ..models import EventSource, EventType, SecurityEvent, Severity

SUSPICIOUS_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".exe",
    ".scr",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".lnk",
    ".msi",
    ".jar",
    ".py",
}

MAX_SCAN_DEPTH = 2
MAX_SCAN_FILES = 500
HASH_CHUNK = 1024 * 1024


class EventSink(Protocol):
    async def publish(self, event: SecurityEvent) -> None: ...


class EventBus:
    """Fan-out bus with a bounded history for the SOC cockpit and tests."""

    def __init__(self, history_size: int = 1000) -> None:
        self._subscribers: list[Callable[[SecurityEvent], Awaitable[None]]] = []
        self._history: Deque[SecurityEvent] = deque(maxlen=history_size)

    def subscribe(self, callback: Callable[[SecurityEvent], Awaitable[None]]) -> None:
        self._subscribers.append(callback)

    async def publish(self, event: SecurityEvent) -> None:
        self._history.append(event)
        for callback in list(self._subscribers):
            await callback(event)

    @property
    def history(self) -> list[SecurityEvent]:
        return list(self._history)

    def latest(self) -> SecurityEvent | None:
        return self._history[-1] if self._history else None


@dataclass
class Partition:
    device: str
    mountpoint: str
    fstype: str = ""
    opts: str = ""

    @property
    def removable_hint(self) -> bool:
        # Deliberately excludes the mountpoint: a folder named "usb" or a test
        # directory must not make a fixed volume look like removable media.
        lowered = f"{self.fstype} {self.opts}".lower()
        return any(token in lowered for token in ("removable", "vfat", "exfat"))

    @property
    def is_removable(self) -> bool:
        """Best-effort removable-media check.

        Mounting a network share, an ISO/VHD image or a phone over MTP also
        produces a new partition. Treating those as a physical USB insertion
        would fabricate the exact physical event this project claims to detect.
        We therefore only accept explicit removable hints or removable-media
        filesystems; everything else is ignored.
        """
        if self.removable_hint:
            return True
        return str(self.fstype).lower() in {"vfat", "exfat", "fat", "fat32", "msdos"}


def default_partition_provider() -> Iterable[Partition]:
    if psutil is None:
        return []
    partitions = []
    for part in psutil.disk_partitions(all=False):
        partitions.append(
            Partition(
                device=getattr(part, "device", "") or "",
                mountpoint=getattr(part, "mountpoint", "") or "",
                fstype=getattr(part, "fstype", "") or "",
                opts=getattr(part, "opts", "") or "",
            )
        )
    return partitions


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def scan_volume(mountpoint: Path) -> list[dict[str, Any]]:
    """Return suspicious files at rest on a volume (never executes anything)."""
    findings: list[dict[str, Any]] = []
    if not mountpoint.exists() or not mountpoint.is_dir():
        return findings

    stack: list[tuple[Path, int]] = [(mountpoint, 0)]
    scanned = 0
    while stack and scanned < MAX_SCAN_FILES:
        current, depth = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if scanned >= MAX_SCAN_FILES:
                break
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 <= MAX_SCAN_DEPTH:
                        stack.append((Path(entry.path), depth + 1))
                    continue
            except OSError:
                continue
            scanned += 1
            path = Path(entry.path)
            if path.suffix.lower() not in SUSPICIOUS_EXTENSIONS:
                continue
            try:
                size = path.stat().st_size
                digest = sha256_file(path)
            except (PermissionError, OSError):
                continue
            findings.append(
                {
                    "path": str(path),
                    "name": path.name,
                    "extension": path.suffix.lower(),
                    "size": size,
                    "sha256": digest,
                }
            )
    return findings


class USBWatcher:
    name = "usb-watcher"

    def __init__(
        self,
        bus: EventSink,
        *,
        partition_provider: Callable[[], Iterable[Partition]] | None = None,
        poll_interval: float = 1.0,
        scan_extensions: set[str] | None = None,
    ) -> None:
        self.bus = bus
        self.partition_provider = partition_provider or default_partition_provider
        self.poll_interval = poll_interval
        self.scan_extensions = scan_extensions or SUSPICIOUS_EXTENSIONS
        self._known: dict[str, Partition] = {}
        self._primed = False
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def poll_once(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        current: dict[str, Partition] = {}
        for part in self.partition_provider():
            if part.mountpoint:
                current[part.mountpoint] = part

        if not self._primed:
            self._known = current
            self._primed = True
            return events

        for mountpoint, part in current.items():
            if mountpoint in self._known:
                continue
            if not part.is_removable:
                # Ignore fixed/network/image mounts: they are not physical media.
                continue
            events.append(self._on_inserted(part))
        for mountpoint, part in self._known.items():
            if mountpoint not in current:
                if not part.is_removable:
                    continue
                events.append(self._on_removed(part))

        self._known = current
        return events

    def _on_inserted(self, part: Partition) -> SecurityEvent:
        findings = scan_volume(Path(part.mountpoint))
        severity = Severity.HIGH if findings else Severity.MEDIUM
        return SecurityEvent(
            source=EventSource.USB,
            type=EventType.USB_INSERTED,
            severity=severity,
            summary=(
                f"Removable media mounted at {part.mountpoint}"
                + (f" with {len(findings)} suspicious file(s)" if findings else "")
            ),
            payload={
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "opts": part.opts,
                "removable_hint": part.removable_hint,
                "is_removable": part.is_removable,
                "findings": findings,
                "autorun_executed": False,
            },
        )

    def _on_removed(self, part: Partition) -> SecurityEvent:
        return SecurityEvent(
            source=EventSource.USB,
            type=EventType.USB_REMOVED,
            severity=Severity.INFO,
            summary=f"Removable media unmounted from {part.mountpoint}",
            payload={"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype},
        )

    async def _run(self) -> None:
        while not self._stop.is_set():
            for event in self.poll_once():
                await self.bus.publish(event)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                continue

    async def start(self) -> "USBWatcher":
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name=self.name)
        return self

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None


class NetWatcher:
    """Tails the target service JSONL request log and flags suspicious calls."""

    name = "net-watcher"

    EMIT_FLAGS = (
        "sqli_marker:",
        "exfil_marker:",
        "admin_command",
        "revoked_session",
    )

    def __init__(
        self,
        bus: EventSink,
        log_path: Path | str | None = None,
        *,
        poll_interval: float = 0.5,
        ignore_history: bool = True,
    ) -> None:
        self.bus = bus
        self.log_path = Path(log_path or get_settings().request_log_path)
        self.poll_interval = poll_interval
        self.ignore_history = ignore_history
        self._offset = 0
        self._primed = False
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def _should_emit(self, entry: dict[str, Any]) -> bool:
        path = str(entry.get("path", ""))
        if path.startswith(("/internal", "/health")):
            return False
        flags = entry.get("flags") or []
        return any(str(flag).startswith(self.EMIT_FLAGS) for flag in flags)

    def _severity(self, entry: dict[str, Any]) -> Severity:
        flags = " ".join(entry.get("flags") or [])
        if "admin_command" in flags:
            return Severity.HIGH
        if "sqli_marker" in flags or "exfil_marker" in flags:
            return Severity.CRITICAL
        if "revoked_session" in flags:
            return Severity.HIGH
        return Severity.MEDIUM

    def _event_type(self, entry: dict[str, Any]) -> EventType:
        if "admin_command" in (entry.get("flags") or []):
            return EventType.ADMIN_COMMAND
        return EventType.SUSPICIOUS_API_REQUEST

    def poll_once(self) -> list[SecurityEvent]:
        if not self.log_path.exists():
            return []

        events: list[SecurityEvent] = []
        size = self.log_path.stat().st_size
        if not self._primed:
            self._primed = True
            if self.ignore_history:
                # Starting from the end prevents replaying yesterday's attacks on
                # process start (which would block our own control plane).
                self._offset = size
                return []
        if size < self._offset:
            self._offset = 0

        with self.log_path.open("rb") as handle:
            handle.seek(self._offset)
            for raw in handle:
                self._offset = handle.tell()
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict) or not self._should_emit(entry):
                    continue
                events.append(
                    SecurityEvent(
                        source=EventSource.NETWORK,
                        type=self._event_type(entry),
                        severity=self._severity(entry),
                        summary=(
                            f"{entry.get('method', '?')} {entry.get('path', '?')} "
                            f"from {entry.get('ip', '?')} -> HTTP {entry.get('status')}"
                        ),
                        payload=entry,
                    )
                )
        return events

    async def _run(self) -> None:
        while not self._stop.is_set():
            for event in self.poll_once():
                await self.bus.publish(event)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                continue

    async def start(self) -> "NetWatcher":
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name=self.name)
        return self

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None


async def wait_for_event(
    bus: EventBus,
    predicate: Callable[[SecurityEvent], bool],
    timeout: float = 5.0,
) -> SecurityEvent:
    """Test helper: wait until a matching event lands on the bus."""
    deadline = time.monotonic() + timeout
    seen = 0
    while time.monotonic() < deadline:
        history = bus.history
        for event in history[seen:]:
            if predicate(event):
                return event
        seen = len(history)
        await asyncio.sleep(0.05)
    raise TimeoutError("matching event not published in time")


def make_watchers(bus: EventSink) -> tuple[USBWatcher, NetWatcher]:
    return USBWatcher(bus), NetWatcher(bus)


__all__ = [
    "EventBus",
    "Partition",
    "USBWatcher",
    "NetWatcher",
    "default_partition_provider",
    "scan_volume",
    "sha256_file",
    "wait_for_event",
    "make_watchers",
]
