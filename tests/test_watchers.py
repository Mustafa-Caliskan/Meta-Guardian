import asyncio
import json
from pathlib import Path

from backend.edge.usb_net_watcher import (
    EventBus,
    NetWatcher,
    Partition,
    USBWatcher,
    sha256_file,
    wait_for_event,
)
from backend.models import EventSource, EventType, SecurityEvent, Severity


class FakePartitions:
    def __init__(self, partitions: list[Partition]):
        self.partitions = partitions

    def __call__(self) -> list[Partition]:
        return list(self.partitions)


def test_usb_watcher_detects_new_volume_with_payload(tmp_path: Path):
    provider = FakePartitions([])
    watcher = USBWatcher(EventBus(), partition_provider=provider)
    assert watcher.poll_once() == []  # priming call

    usb_root = tmp_path / "usb"
    usb_root.mkdir()
    payload = usb_root / "payload.ps1"
    payload.write_text("Write-Host 'staged'", encoding="utf-8")
    (usb_root / "notes.txt").write_text("hello", encoding="utf-8")

    provider.partitions = [Partition(device="E:", mountpoint=str(usb_root), fstype="FAT32", opts="removable")]
    events = watcher.poll_once()

    assert len(events) == 1
    event = events[0]
    assert event.type is EventType.USB_INSERTED
    assert event.severity is Severity.HIGH
    findings = event.payload["findings"]
    assert len(findings) == 1
    assert findings[0]["name"] == "payload.ps1"
    assert findings[0]["sha256"] == sha256_file(payload)
    assert event.payload["autorun_executed"] is False


def test_usb_watcher_reports_removal(tmp_path: Path):
    usb_root = tmp_path / "usb"
    usb_root.mkdir()
    provider = FakePartitions(
        [Partition(device="E:", mountpoint=str(usb_root), fstype="exFAT", opts="removable")]
    )
    watcher = USBWatcher(EventBus(), partition_provider=provider)
    watcher.poll_once()

    provider.partitions = []
    events = watcher.poll_once()

    assert len(events) == 1
    assert events[0].type is EventType.USB_REMOVED
    assert events[0].severity is Severity.INFO


def test_usb_watcher_clean_volume_is_medium(tmp_path: Path):
    provider = FakePartitions([])
    watcher = USBWatcher(EventBus(), partition_provider=provider)
    watcher.poll_once()

    usb_root = tmp_path / "usb"
    usb_root.mkdir()
    (usb_root / "readme.txt").write_text("nothing", encoding="utf-8")
    provider.partitions = [
        Partition(device="E:", mountpoint=str(usb_root), fstype="FAT32", opts="removable")
    ]

    events = watcher.poll_once()
    assert events[0].severity is Severity.MEDIUM
    assert events[0].payload["findings"] == []
    assert events[0].payload["is_removable"] is True


def test_usb_watcher_ignores_fixed_and_network_mounts(tmp_path: Path):
    provider = FakePartitions([])
    watcher = USBWatcher(EventBus(), partition_provider=provider)
    watcher.poll_once()

    fixed = tmp_path / "fixed"
    fixed.mkdir()
    (fixed / "payload.ps1").write_text("staged", encoding="utf-8")
    provider.partitions = [
        Partition(device="C:", mountpoint=str(fixed), fstype="NTFS", opts="rw,fixed"),
        Partition(device="Z:", mountpoint=str(tmp_path / "share"), fstype="NTFS", opts="rw"),
    ]

    assert watcher.poll_once() == []


def test_usb_watcher_accepts_explicit_removable_opt(tmp_path: Path):
    provider = FakePartitions([])
    watcher = USBWatcher(EventBus(), partition_provider=provider)
    watcher.poll_once()

    usb_root = tmp_path / "usb"
    usb_root.mkdir()
    (usb_root / "payload.ps1").write_text("staged", encoding="utf-8")
    provider.partitions = [
        Partition(device="E:", mountpoint=str(usb_root), fstype="NTFS", opts="rw,removable")
    ]

    events = watcher.poll_once()
    assert len(events) == 1
    assert events[0].payload["is_removable"] is True


def _write_log(path: Path, entries: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8"
    )


def test_net_watcher_emits_only_suspicious_entries(tmp_path: Path):
    log = tmp_path / "requests.jsonl"
    _write_log(
        log,
        [
            {
                "seq": 1,
                "ip": "10.0.0.21",
                "method": "GET",
                "path": "/health",
                "query": "",
                "status": 200,
                "flags": [],
            },
            {
                "seq": 2,
                "ip": "203.0.113.66",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL&limit=99999",
                "status": 200,
                "flags": ["exfil_marker:aircraft=all", "exfil_marker:limit=99999"],
            },
            {
                "seq": 3,
                "ip": "10.0.0.50",
                "method": "GET",
                "path": "/api/v1/ops/scan",
                "query": "",
                "status": 200,
                "flags": [],
            },
        ],
    )
    watcher = NetWatcher(EventBus(), log, ignore_history=False)
    events = watcher.poll_once()

    assert len(events) == 1
    assert events[0].type is EventType.SUSPICIOUS_API_REQUEST
    assert events[0].severity is Severity.CRITICAL
    assert events[0].payload["seq"] == 2


def test_net_watcher_is_incremental_and_survives_truncation(tmp_path: Path):
    log = tmp_path / "requests.jsonl"
    _write_log(
        log,
        [
            {
                "seq": 1,
                "ip": "203.0.113.66",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL",
                "status": 200,
                "flags": ["exfil_marker:aircraft=all"],
            }
        ],
    )
    watcher = NetWatcher(EventBus(), log, ignore_history=False)
    assert len(watcher.poll_once()) == 1
    assert watcher.poll_once() == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "seq": 2,
                    "ip": "203.0.113.66",
                    "method": "POST",
                    "path": "/api/v1/admin/command",
                    "query": "",
                    "status": 200,
                    "flags": ["admin_command"],
                }
            )
            + "\n"
        )
    second = watcher.poll_once()
    assert len(second) == 1
    assert second[0].type is EventType.ADMIN_COMMAND

    log.write_text("", encoding="utf-8")
    assert watcher.poll_once() == []


def test_event_bus_publishes_to_subscribers():
    async def scenario():
        bus = EventBus()
        received = []

        async def callback(event):
            received.append(event)

        bus.subscribe(callback)
        await bus.publish(
            SecurityEvent(source=EventSource.USB, type=EventType.USB_INSERTED)
        )
        assert len(received) == 1
        assert bus.latest() is received[0]

    asyncio.run(scenario())


def test_wait_for_event_helper():
    async def scenario():
        bus = EventBus()

        async def publisher():
            await asyncio.sleep(0.05)
            await bus.publish(
                SecurityEvent(
                    source=EventSource.NETWORK,
                    type=EventType.SUSPICIOUS_API_REQUEST,
                )
            )

        task = asyncio.create_task(publisher())
        event = await wait_for_event(bus, lambda e: e.type is EventType.SUSPICIOUS_API_REQUEST)
        await task
        assert event.type is EventType.SUSPICIOUS_API_REQUEST

    asyncio.run(scenario())


def test_net_watcher_ignores_verification_probes(tmp_path: Path):
    log = tmp_path / "requests.jsonl"
    _write_log(
        log,
        [
            {
                "seq": 1,
                "ip": "172.19.0.3",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL&limit=99999",
                "status": 200,
                "flags": ["exfil_marker:aircraft=all"],
                "probe": True,
            },
            {
                "seq": 2,
                "ip": "203.0.113.66",
                "method": "GET",
                "path": "/api/v1/ops/data",
                "query": "aircraft=ALL&limit=99999",
                "status": 200,
                "flags": ["exfil_marker:aircraft=all"],
                "probe": False,
            },
        ],
    )
    watcher = NetWatcher(EventBus(), log, ignore_history=False)
    events = watcher.poll_once()

    assert len(events) == 1
    assert events[0].payload["ip"] == "203.0.113.66"
