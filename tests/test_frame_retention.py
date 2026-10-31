"""Task 7 — raw frame retention.

Frames are the only evidence that is actually personal data: the mask and the
hash prove what the system saw without keeping the picture. The purge therefore
deletes ``frame.png`` only and must never touch masks, receipts or the ledger.

Age is decided by file modification time: the file is what is on disk, it
survives restarts, and tests can age it deterministically with ``os.utime``.
"""

import os
import time
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import LLMMode, Settings
from backend.main import AppState, create_app
from tests.support import FakeMCP


def build_state(tmp_path: Path, *, retention_days: int = 7) -> AppState:
    settings = Settings(
        mode=LLMMode.MOCK,
        target_port=1,
        fixtures_dir=tmp_path / "fixtures",
        runtime_dir=tmp_path / "runtime",
        quarantine_dir=tmp_path / "quarantine",
        change_tickets_path=tmp_path / "tickets.json",
        persist_incidents=True,
        segmentation_async=False,
        frame_retention_days=retention_days,
    )
    settings.ensure_dirs()
    frame = np.zeros((120, 160, 3), dtype=np.uint8)
    return AppState(
        settings=settings,
        mcp=FakeMCP(),
        enable_watchers=False,
        runtime_dir=tmp_path / "runtime",
        scenarios_dir=tmp_path / "scenarios",
        frame_provider=lambda: frame.copy(),
    )


def evidence(state: AppState, incident_id: str) -> Path:
    directory = state.evidence_dir(incident_id)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def age(path: Path, days: float) -> None:
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


def test_expired_frame_is_deleted_but_mask_and_receipt_survive(tmp_path: Path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        directory = evidence(state, incident["id"])
        frame = directory / "frame.png"
        mask = directory / "mask.png"
        receipt = directory / "frame.sha256"
        for path in (frame, mask, receipt):
            path.write_bytes(b"evidence")

        age(frame, 8)
        removed = state.purge_expired_frames()

        assert removed == [str(frame)]
        assert not frame.exists()
        assert mask.exists()
        assert receipt.exists()


def test_recent_frame_is_kept(tmp_path: Path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)):
        directory = evidence(state, "inc_recent")
        frame = directory / "frame.png"
        frame.write_bytes(b"fresh")
        age(frame, 1)

        assert state.purge_expired_frames() == []
        assert frame.exists()


def test_retention_zero_disables_the_purge(tmp_path: Path):
    state = build_state(tmp_path, retention_days=0)
    with TestClient(create_app(state)):
        directory = evidence(state, "inc_forever")
        frame = directory / "frame.png"
        frame.write_bytes(b"ancient")
        age(frame, 3650)

        assert state.purge_expired_frames() == []
        assert frame.exists()


def test_purge_runs_at_startup(tmp_path: Path):
    state = build_state(tmp_path)
    directory = evidence(state, "inc_old")
    frame = directory / "frame.png"
    frame.write_bytes(b"stale")
    age(frame, 30)

    with TestClient(create_app(state)):
        assert not frame.exists()


def test_purged_frame_does_not_break_the_integrity_chain(tmp_path: Path):
    state = build_state(tmp_path)
    with TestClient(create_app(state)) as client:
        incident = client.post("/api/simulate", json={"scenario": "A"}).json()
        frame = evidence(state, incident["id"]) / "frame.png"
        assert frame.exists()
        age(frame, 30)
        state.purge_expired_frames()
        assert not frame.exists()

        check = client.get(
            f"/api/incidents/{incident['id']}/casefile?format=json&verify=1"
        ).json()
        assert check["integrity"]["chain_valid"] is True


def test_config_advertises_the_retention_policy(tmp_path: Path):
    state = build_state(tmp_path, retention_days=3)
    with TestClient(create_app(state)) as client:
        policy = client.get("/api/config").json()["data_retention"]

    assert policy["frame_retention_days"] == 3
    assert policy["masks_and_hashes_retained"] is True
    assert "deleted" in policy["note"]


def test_retention_defaults_to_seven_days():
    settings = Settings(mode=LLMMode.MOCK)
    assert settings.frame_retention_days == 7
