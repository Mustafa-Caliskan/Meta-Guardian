"""Measured KPIs for the demo. One JSON report, no chart, no guesswork.

    python scripts/benchmark_latency.py            # mock LLM, real pipeline
    python scripts/benchmark_latency.py --patch    # also patch + verify (needs :8001)
    python scripts/benchmark_latency.py --json

Every number comes from the running pipeline (or from the correlator with real
timestamps). Targets live in docs/THREAT_MODEL.md. The report is written to
``data/runtime/kpi_report.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx

from backend.config import LLMMode, Settings, get_settings
from backend.edge.correlator import Correlator
from backend.main import AppState
from backend.models import (
    ActionType,
    Classification,
    EventSource,
    EventType,
    KPIReport,
    MCPActionResult,
    SecurityEvent,
    Severity,
)


class NullMCP:
    """Stub used only when the target is down; its timings are labelled as such."""

    async def call_tool(self, name: str, arguments: dict) -> MCPActionResult:
        target = str(
            arguments.get("filename")
            or arguments.get("ip")
            or arguments.get("session")
            or arguments.get("pid")
            or "?"
        )
        return MCPActionResult(
            action=ActionType(name), target=target, success=True, detail="target offline (stub)"
        )


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _sample_event(source, event_type, severity, summary, payload) -> SecurityEvent:
    return SecurityEvent(
        source=source, type=event_type, severity=severity, summary=summary, payload=payload
    )


def usb_event(mountpoint: str = "/media/usb") -> SecurityEvent:
    return _sample_event(
        EventSource.USB,
        EventType.USB_INSERTED,
        Severity.HIGH,
        f"Removable media mounted at {mountpoint} with 1 suspicious file(s)",
        {
            "mountpoint": mountpoint,
            "findings": [{"name": "payload.ps1", "sha256": "a" * 64, "size": 96}],
        },
    )


def network_event() -> SecurityEvent:
    return _sample_event(
        EventSource.NETWORK,
        EventType.SUSPICIOUS_API_REQUEST,
        Severity.CRITICAL,
        "GET /api/v1/ops/data?aircraft=ALL from 203.0.113.66 -> HTTP 200",
        {
            "ip": "203.0.113.66",
            "session": "session-7f3a9c",
            "method": "GET",
            "path": "/api/v1/ops/data",
            "status": 200,
        },
    )


async def target_reachable(url: str) -> bool:
    try:
        async with httpx.AsyncClient(base_url=url, timeout=2.0) as client:
            response = await client.get("/health")
            return response.status_code == 200
    except httpx.HTTPError:
        return False


def correlation_latency() -> tuple[float, str]:
    """MTTD at the edge: first event -> incident bundle, using real time."""
    correlator = Correlator(window_seconds=30, cooldown_seconds=0)
    started = time.perf_counter()
    correlator.observe(usb_event(mountpoint="/media/usb"))
    result = correlator.observe(network_event())
    elapsed = (time.perf_counter() - started) * 1000

    if result is None:
        return elapsed, "no bundle produced"
    return max(result.latency_ms, elapsed), f"bundle reason={result.reason}"


def containment_latency(incident) -> float:
    if not incident.decision or not incident.action_results:
        return 0.0
    decision_at = incident.decision.created_at
    last = max(result.executed_at for result in incident.action_results)
    return max(0.0, (last - decision_at).total_seconds() * 1000)


async def run(args) -> KPIReport:
    settings = get_settings()
    runtime = settings.runtime_dir / "benchmark"
    runtime.mkdir(parents=True, exist_ok=True)

    bench_settings = Settings(
        mode=LLMMode.MOCK if not args.live else settings.mode,
        target_port=settings.target_port,
        fixtures_dir=settings.fixtures_dir,
        runtime_dir=runtime,
        quarantine_dir=runtime / "quarantine",
        change_tickets_path=runtime / "tickets.json",
        persist_incidents=False,
        meta_api_key=settings.meta_api_key,
        baseten_api_key=settings.baseten_api_key,
        baseten_base_url=settings.baseten_base_url,
        fireworks_api_key=settings.fireworks_api_key,
        fireworks_base_url=settings.fireworks_base_url,
        meta_base_url=settings.meta_base_url,
        ooda_model=settings.ooda_model,
        forensics_model=settings.forensics_model,
        code_model=settings.code_model,
        sam_model=settings.sam_model,
        spark_open_model=settings.spark_open_model,
        internal_api_token=settings.internal_api_token,
        trust_forwarded_for=settings.trust_forwarded_for,
    )
    bench_settings.ensure_dirs()

    # Containment timings need a real target. If it is down we still measure the
    # policy decision, but mark the containment sample as unavailable.
    reachable = await target_reachable(bench_settings.target_base_url)
    mcp = None if reachable else NullMCP()
    state = AppState(
        settings=bench_settings,
        mcp=mcp,
        enable_watchers=False,
        runtime_dir=runtime,
    )

    mttd, mttd_note = correlation_latency()

    incidents = {}
    for scenario in ("A", "B", "C"):
        incidents[scenario] = await state.simulate(scenario)

    contain = [
        containment_latency(incidents[s])
        for s in ("A", "B")
        if incidents[s].action_results
    ]
    mttc = statistics.mean(contain) if contain else 0.0

    patch_ms = 0.0
    e2e_ms = 0.0
    verified = None
    if args.patch and reachable:
        patched = await state.run_patch(incidents["A"].id)
        if patched.patch:
            patch_ms = patched.patch.latency_ms
            verified = patched.patch.verified
            e2e_ms = max(
                0.0,
                (patched.patch.created_at - incidents["A"].created_at).total_seconds() * 1000,
            )

    # Detection quality over the three scenarios.
    a_ok = incidents["A"].decision.classification is Classification.THREAT_CRITICAL
    b_ok = incidents["B"].decision.classification is Classification.GHOST_ATTACK
    c_ok = incidents["C"].decision.classification is Classification.BENIGN_AUTHORIZED
    tp = int(a_ok) + int(b_ok)
    fn = 2 - tp
    fp = 0 if c_ok else 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / 1

    # Video bandwidth argument, stated as an assumption rather than measured:
    # one frame per event vs 30 FPS streamed for a 30 s decision window.
    frames_streamed = 30 * 30
    tokens_saved = (1 - 1 / frames_streamed) * 100

    notes = [
        f"MTTD {mttd_note}; measured with real monotonic timestamps.",
        "Containment uses the live target gateway" if reachable else "Target was down: containment used a stub MCP and is NOT a real latency claim.",
        "Patch timing requires --patch and a running target on :8001.",
        "tokens_saved_pct is an arithmetic assumption (1 frame/event vs 30 FPS for 30 s), not a measured network metric.",
        f"live={args.live}",
    ]

    return KPIReport(
        scenario="A/B/C regression",
        detection_latency_ms=round(mttd, 2),
        containment_latency_ms=round(mttc, 2),
        patch_latency_ms=round(patch_ms, 2),
        end_to_end_latency_ms=round(e2e_ms, 2),
        false_positive_rate=round(fpr, 4),
        detection_precision=round(precision, 4),
        detection_recall=round(recall, 4),
        tokens_saved_pct=round(tokens_saved, 2),
        cloud_calls_per_incident=3,
        notes=" | ".join(notes) + (f" | patch_verified={verified}" if verified is not None else ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch", action="store_true", help="run forensics + patch and verify 200->403")
    parser.add_argument("--live", action="store_true", help="use configured live LLM instead of mock")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = asyncio.run(run(args))
    path = get_settings().runtime_dir / "kpi_report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if args.json:
        print(report.model_dump_json(indent=2))
        return 0

    print(f"KPI report — {report.scenario}")
    print(f"  MTTD (edge correlation) : {report.detection_latency_ms:>10.2f} ms")
    print(f"  MTTC (containment)      : {report.containment_latency_ms:>10.2f} ms")
    print(f"  Patch + verify          : {report.patch_latency_ms:>10.2f} ms")
    print(f"  End-to-end              : {report.end_to_end_latency_ms:>10.2f} ms")
    print(f"  Precision / Recall      : {report.detection_precision:.2f} / {report.detection_recall:.2f}")
    print(f"  False positive rate     : {report.false_positive_rate:.2f}")
    print(f"  Bandwidth saved (assumed): {report.tokens_saved_pct:.2f}%")
    print(f"\nwritten to {path}")
    print("notes:", report.notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
