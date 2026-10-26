import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.generate_data import (
    ATTACKER_IP,
    LOG_FILENAME,
    MANIFEST_FILENAME,
    build_archive,
    verify_manifest,
)


def test_archive_is_deterministic(tmp_path: Path):
    end = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
    _, first = build_archive(days=30, seed=1337, end=end, out_dir=tmp_path / "a")
    _, second = build_archive(days=30, seed=1337, end=end, out_dir=tmp_path / "b")
    assert first["sha256"] == second["sha256"]
    assert first["total_lines"] == second["total_lines"]


def test_hidden_recon_is_three_days_before_incident(tmp_path: Path):
    end = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
    _, manifest = build_archive(days=30, seed=1337, end=end, out_dir=tmp_path)

    recon = datetime.fromisoformat(manifest["recon"]["first_timestamp"])
    incident = datetime.fromisoformat(manifest["incident"]["timestamp"])
    delta_days = (incident - recon).total_seconds() / 86400
    assert 2.99 < delta_days < 3.05
    assert manifest["recon"]["ip"] == ATTACKER_IP
    assert len(manifest["recon"]["lines"]) >= 5


def test_manifest_citations_are_line_verifiable(tmp_path: Path):
    end = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
    _, manifest = build_archive(days=30, seed=1337, end=end, out_dir=tmp_path / "logs")

    checks = verify_manifest(manifest)
    assert all(check["exists"] and check["excerpt_matches"] for check in checks), checks

    log_path = Path(manifest["log_file"])
    lines = log_path.read_text(encoding="utf-8").splitlines()
    recon_line = lines[manifest["recon"]["first_line"] - 1]
    incident_line = lines[manifest["incident"]["line"] - 1]
    assert ATTACKER_IP in recon_line and "/api/v1/ops/scan" in recon_line
    assert "aircraft=ALL" in incident_line


def test_manifest_is_written_next_to_log(tmp_path: Path):
    end = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
    build_archive(days=5, seed=99, end=end, out_dir=tmp_path)
    manifest_path = tmp_path / MANIFEST_FILENAME
    assert (tmp_path / LOG_FILENAME).exists()
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["total_lines"] > 0
    assert data["attacker_ip"] == ATTACKER_IP
