import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from backend.cloud.citations import excerpt_matches, verify_citation
from backend.cloud.forensics import ArchiveReader, ForensicsEngine, incident_terms
from backend.cloud.patcher import Patcher, choose_markers
from backend.cloud.sanitizer import (
    mask_session,
    redact_secrets,
    safe_path,
    sanitize_bundle,
)
from backend.models import (
    Citation,
    ForensicsReport,
    Incident,
    SecurityEvent,
    VisionEvidence,
)
from tests.support import StubLLM, network_event, usb_event, vision

LOG_LINES = [
    "2026-10-01T00:00:00Z src=10.0.0.5 dst=10.0.0.12 method=GET path=/health status=200",
    "2026-10-04T10:00:00Z src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200",
    "2026-10-07T10:00:00Z src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/data?aircraft=ALL status=200",
]


@pytest.fixture()
def archive(tmp_path: Path):
    log = tmp_path / "siem.log"
    log.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8")
    manifest = tmp_path / "siem_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "recon": {
                    "ip": "203.0.113.66",
                    "first_timestamp": "2026-10-04T10:00:00Z",
                    "lines": [
                        {
                            "line": 2,
                            "timestamp": "2026-10-04T10:00:00Z",
                            "method": "GET",
                            "path": "/api/v1/ops/scan",
                            "status": 200,
                        }
                    ],
                    "citation": {
                        "log_file": "siem.log",
                        "line": 2,
                        "excerpt": "src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200",
                    },
                },
                "incident": {
                    "ip": "203.0.113.66",
                    "line": 3,
                    "timestamp": "2026-10-07T10:00:00Z",
                    "path": "/api/v1/ops/data?aircraft=ALL",
                    "status": 200,
                    "citation": {
                        "log_file": "siem.log",
                        "line": 3,
                        "excerpt": "src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/data?aircraft=ALL status=200",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return log, manifest


def valid_payload(earliest: str | None = "2026-10-04T10:00:00Z") -> dict:
    return {
        "attack_chain": [
            {
                "timestamp": "2026-10-04T10:00:00Z",
                "source_ip": "203.0.113.66",
                "endpoint": "/api/v1/ops/scan",
                "description": "endpoint enumeration",
            }
        ],
        "earliest_discovery": earliest,
        "vulnerable_file": "backend/target_service.py",
        "vulnerable_line": 318,
        "vulnerable_code": "missing session check on /api/v1/ops/data",
        "summary": "Reconnaissance preceded the exfiltration.",
        "citations": [
            {
                "log_file": "siem.log",
                "line": 2,
                "excerpt": "src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200",
            }
        ],
    }


# --------------------------------------------------------------------- sanitizer


def test_redact_secrets_removes_keys_and_bearer_tokens():
    text = "key sk-abcdefghijklmnop and Bearer abcdefghijklmnopqrstuvwxyz"
    redacted = redact_secrets(text)
    assert "sk-abcdefghijklmnop" not in redacted
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "[REDACTED]" in redacted


def test_safe_path_hides_the_user_profile():
    assert safe_path("C:\\Users\\mustafa\\secret\\payload.ps1") == "secret/payload.ps1"
    assert safe_path("/home/mustafa/archive/siem.log") == "archive/siem.log"
    assert safe_path(None) is None


def test_session_masking():
    assert mask_session("session-7f3a9c") == "session-***"
    assert mask_session("session-7f3a9c-very-long-token") == "session-***"
    assert mask_session("-") == "none"


def test_sanitize_bundle_sends_no_image_bytes():
    bundle = sanitize_bundle(
        [usb_event("/home/mustafa/usb"), network_event()],
        vision(True),
    )
    serialized = json.dumps(bundle)
    assert "frame" not in serialized.lower() or "frame_sent_to_cloud" in serialized
    assert bundle["vision"]["frame_sent_to_cloud"] is False
    assert bundle["vision"]["operator_present"] is True
    assert "mustafa" not in serialized
    assert bundle["events"][0]["mountpoint"] == "usb"


# --------------------------------------------------------------------- citations


def test_excerpt_matching_supports_wildcards():
    line = "2026-10-04 src=203.0.113.66 path=/api/v1/ops/scan status=200"
    assert excerpt_matches(line, "src=203.0.113.66 ... path=/api/v1/ops/scan")
    assert not excerpt_matches(line, "src=198.51.100.1")


def test_verify_citation_rejects_invented_lines(tmp_path: Path):
    check = verify_citation(
        Citation(log_file="missing.log", line=1, excerpt="anything"), tmp_path
    )
    assert check.exists is False
    assert check.excerpt_matches is False


# --------------------------------------------------------------------- forensics


def test_incident_terms_prioritise_attacker_signals():
    terms = incident_terms([usb_event(), network_event()], vision(True))
    assert "203.0.113.66" in terms
    assert "payload.ps1" in terms
    assert terms.index("203.0.113.66") < terms.index("ops/scan")


def test_archive_index_includes_attacker_lines_not_just_noise(tmp_path: Path):
    log = tmp_path / "mixed.log"
    lines = [
        f"2026-10-01T00:00:{i:02d}Z src=10.0.0.50 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200"
        for i in range(40)
    ]
    lines.append(
        "2026-10-04T10:00:00Z src=203.0.113.66 dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200"
    )
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    index = ArchiveReader(log).build_index(["203.0.113.66", "ops/scan"])
    texts = [excerpt.text for excerpt in index.excerpts]
    assert any("203.0.113.66" in text for text in texts)


async def test_forensics_accepts_verified_citations(archive):
    log, manifest = archive
    engine = ForensicsEngine(
        StubLLM(valid_payload()),
        reader=ArchiveReader(log),
        manifest_path=manifest,
        project_root=log.parent,
    )

    report = await engine.analyze("inc_test", [network_event()], vision(True))

    assert report.model == "stub-model"
    assert report.citations_verified is True
    assert len(report.citations) == 1
    assert report.recon_verified is True
    assert report.attack_chain and report.attack_chain[0].source_ip == "203.0.113.66"
    assert report.vulnerable_line == 318
    assert report.archive_lines_scanned == 3


async def test_forensics_flags_an_off_manifest_earliest_discovery(archive):
    log, manifest = archive
    engine = ForensicsEngine(
        StubLLM(valid_payload(earliest="2026-09-01T00:00:00Z")),
        reader=ArchiveReader(log),
        manifest_path=manifest,
        project_root=log.parent,
    )

    report = await engine.analyze("inc_test", [network_event()], vision(True))

    assert report.recon_verified is False
    assert "off by" in report.summary


async def test_forensics_drops_invented_citations_and_uses_manifest(archive):
    log, manifest = archive
    payload = valid_payload()
    payload["citations"] = [
        {"log_file": "siem.log", "line": 999, "excerpt": "invented line"}
    ]
    engine = ForensicsEngine(
        StubLLM(payload),
        reader=ArchiveReader(log),
        manifest_path=manifest,
        project_root=log.parent,
    )

    report = await engine.analyze("inc_test", [network_event()], vision(True))

    assert report.model == "manifest-fallback"
    assert report.citations_verified is True
    assert all(citation.line in (2, 3) for citation in report.citations)
    assert "failed line verification" in report.summary


async def test_forensics_survives_llm_failure(archive):
    log, manifest = archive
    engine = ForensicsEngine(
        StubLLM(error=RuntimeError("provider down")),
        reader=ArchiveReader(log),
        manifest_path=manifest,
        project_root=log.parent,
    )

    report = await engine.analyze("inc_test", [network_event()], vision(True))

    assert report.model == "manifest-fallback"
    assert "provider down" in report.summary
    assert report.citations_verified is True


async def test_forensics_without_archive_is_honest(tmp_path: Path):
    engine = ForensicsEngine(
        StubLLM(valid_payload()),
        reader=ArchiveReader(tmp_path / "missing.log"),
        manifest_path=tmp_path / "missing.json",
        project_root=tmp_path,
    )

    report = await engine.analyze("inc_test", [network_event()], vision(True))

    assert "SIEM archive not found" in report.summary
    assert report.citations == []


# ------------------------------------------------------------------------ patcher


def gateway_transport(*, patch_effective: bool = True, calls: list | None = None):
    calls = calls if calls is not None else []
    state = {"applied": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/internal/gateway/apply_rule":
            state["applied"] = True
            return httpx.Response(200, json={"applied": True, "revision": 1})
        if path == "/internal/gateway/rollback":
            state["applied"] = False
            return httpx.Response(200, json={"rolled_back": True, "revision": 2})
        if path == "/api/v1/ops/data":
            status = 403 if (state["applied"] and patch_effective) else 200
            return httpx.Response(status, json={"status": status})
        return httpx.Response(404, json={"detail": "unknown"})

    return httpx.MockTransport(handler), calls


def sample_incident() -> Incident:
    return Incident(events=[usb_event(), network_event()])


def sample_report() -> ForensicsReport:
    return ForensicsReport(
        incident_id="inc_test",
        vulnerable_file="backend/target_service.py",
        summary="mass exfiltration of aircraft data",
        model="stub-model",
    )


async def test_patcher_verifies_200_to_403():
    transport, calls = gateway_transport(patch_effective=True)
    patcher = Patcher(target_base_url="http://gw", transport=transport)

    result = await patcher.patch(sample_incident(), sample_report())

    assert result.applied is True
    assert result.before_status == 200
    assert result.after_status == 403
    assert result.verified is True
    assert result.rolled_back is False
    assert "PATCH VERIFIED" in result.verification_note
    assert result.rule_fingerprint and len(result.rule_fingerprint) == 16
    assert result.patch_code.startswith("template=")
    assert "/internal/gateway/apply_rule" in calls


async def test_patcher_rolls_back_when_the_patch_does_not_work():
    transport, calls = gateway_transport(patch_effective=False)
    patcher = Patcher(target_base_url="http://gw", transport=transport)

    result = await patcher.patch(sample_incident(), sample_report())

    assert result.before_status == 200
    assert result.after_status == 200
    assert result.verified is False
    assert result.rolled_back is True
    assert "/internal/gateway/rollback" in calls


async def test_patcher_reports_a_failed_before_probe():
    async def broken_attack(*args, **kwargs):
        raise httpx.ConnectError("refused")

    patcher = Patcher(target_base_url="http://gw", attack=broken_attack)
    result = await patcher.patch(sample_incident(), sample_report())

    assert result.applied is False
    assert result.before_status is None
    assert "before probe failed" in result.verification_note


async def test_patcher_marks_replays_with_the_internal_token():
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        record = {
            "path": request.url.path,
            "probe": request.headers.get("x-mg-probe", ""),
        }
        seen.append(record)
        if request.url.path == "/api/v1/ops/data":
            return httpx.Response(200)
        return httpx.Response(200, json={"applied": True})

    patcher = Patcher(
        target_base_url="http://gw",
        transport=httpx.MockTransport(handler),
        internal_token="s3cret",
    )
    await patcher.patch(sample_incident(), sample_report())

    probes = [item for item in seen if item["path"] == "/api/v1/ops/data"]
    assert probes and all(item["probe"] == "s3cret" for item in probes)


async def test_patcher_sends_no_probe_header_without_a_token():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/ops/data":
            seen.append(request.headers.get("x-mg-probe", ""))
            return httpx.Response(200)
        return httpx.Response(200, json={"applied": True})

    patcher = Patcher(
        target_base_url="http://gw",
        transport=httpx.MockTransport(handler),
        internal_token="",
    )
    await patcher.patch(sample_incident(), sample_report())

    assert seen and all(value == "" for value in seen)


async def test_patcher_sends_internal_token():
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-internal-token"))
        if request.url.path == "/api/v1/ops/data":
            return httpx.Response(200)
        return httpx.Response(200, json={"applied": True})

    patcher = Patcher(
        target_base_url="http://gw",
        transport=httpx.MockTransport(handler),
        internal_token="secret-token",
    )
    await patcher.patch(sample_incident(), sample_report())

    assert "secret-token" in seen


def test_choose_markers_is_allowlisted():
    report = ForensicsReport(
        incident_id="inc", summary="mass exfiltration via aircraft=ALL dump"
    )
    markers = choose_markers(report)
    assert "aircraft=all" in markers
    assert all(marker in {"aircraft=all", "limit=99999", "export=all", "dump=true", "../", "..\\", "union select", "' or '1'='1", "; drop", "<script", "javascript:"} for marker in markers)
    # the model cannot inject an arbitrary marker
    assert "rm -rf" not in choose_markers(report)


def test_exact_line_for_resolves_and_rejects_ambiguous_matches():
    from scripts.forensics_full_archive import exact_line_for

    lines = [
        "2026-10-01 src=10.0.0.5 path=/health status=200",
        "2026-10-04 src=203.0.113.66 path=/api/v1/ops/scan status=200",
        "2026-10-04 src=203.0.113.66 path=/api/v1/ops/scan status=200",
    ]
    assert exact_line_for(lines, "src=10.0.0.5 path=/health") == 1
    # the excerpt appears twice, so it is ambiguous and must not be auto-corrected
    assert exact_line_for(lines, "path=/api/v1/ops/scan") is None
    assert exact_line_for(lines, "does not exist") is None


def test_verify_payload_corrects_miscounted_lines(tmp_path):
    from scripts.forensics_full_archive import verify_payload

    lines = [
        "2026-10-01 src=10.0.0.5 path=/health status=200",
        "2026-10-04 src=203.0.113.66 path=/api/v1/ops/scan status=200",
    ]
    payload = {
        "citations": [
            {
                "log_file": "data/history_logs/siem_30d.log",
                "line": 999,
                "excerpt": "src=203.0.113.66 path=/api/v1/ops/scan",
            }
        ]
    }
    result = verify_payload(payload, lines)

    assert len(result["citations"]) == 1
    assert result["citations"][0].line == 2
    assert result["corrected"] == [{"claimed_line": 999, "resolved_line": 2}]
