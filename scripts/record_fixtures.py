"""Record real provider responses as replayable fixtures.

The replay mode is only insurance if it actually contains recorded live answers.
This script performs real calls and stores them in ``data/fixtures/{task}.json``
so ``LLM_MODE=replay`` works when the network or credits are gone.

Tasks recorded
--------------
* ``ooda``      — edge decision for a Scenario A bundle
* ``forensics`` — 1M-context report over the SIEM archive

Patch planning is intentionally **not** recorded: the patcher is deterministic
and does not ask a model for code, which is a deliberate safety property.

Usage
-----
    python scripts/record_fixtures.py --model meta-models/muse-spark-open-1026
    python scripts/record_fixtures.py --provider meta --model muse-spark-1.3
    python scripts/record_fixtures.py --list
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.cloud.forensics import ForensicsEngine  # noqa: E402
from backend.config import FIXTURES_DIR, get_settings  # noqa: E402
from backend.edge.ooda_agent import OODA_SYSTEM_PROMPT  # noqa: E402
from backend.llm.factory import RecordingLLM  # noqa: E402
from backend.llm.openai_compat import OpenAICompatLLM  # noqa: E402
from backend.models import (  # noqa: E402
    EventSource,
    EventType,
    SecurityEvent,
    Severity,
    VisionEvidence,
)

SCENARIO_EVENTS = [
    SecurityEvent(
        source=EventSource.USB,
        type=EventType.USB_INSERTED,
        severity=Severity.HIGH,
        summary="Removable media mounted with 1 suspicious file(s)",
        payload={
            "mountpoint": "usb",
            "findings": [
                {
                    "name": "payload.ps1",
                    "extension": ".ps1",
                    "size": 96,
                    "sha256": "a1b2c3d4e5f60718",
                }
            ],
            "autorun_executed": False,
        },
    ),
    SecurityEvent(
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
    ),
]

SCENARIO_VISION = VisionEvidence(
    operator_present=True,
    confidence=0.94,
    roi=[250, 340, 110, 80],
    description="operator-sized motion detected in the camera frame",
    method="baseline_diff->sam-3.1",
    motion_ratio=0.021,
)


def build_live_llm(provider: str, model: str | None, max_tokens: int):
    settings = get_settings()
    if provider == "baseten":
        return OpenAICompatLLM(
            base_url=settings.baseten_base_url,
            api_key=settings.baseten_api_key,
            default_model=model or settings.spark_open_model,
            timeout=settings.request_timeout,
            max_tokens=max_tokens,
            temperature=0.1,
            reasoning_effort="low",
        )
    if provider == "fireworks":
        return OpenAICompatLLM(
            base_url=settings.fireworks_base_url,
            api_key=settings.fireworks_api_key,
            default_model=model or settings.ooda_model,
            timeout=settings.request_timeout,
            max_tokens=max_tokens,
            temperature=0.1,
            reasoning_effort="low",
        )
    return OpenAICompatLLM(
        base_url=settings.meta_base_url,
        api_key=settings.meta_api_key,
        default_model=model or settings.forensics_model,
        timeout=settings.request_timeout,
        max_tokens=max_tokens,
        temperature=0.1,
        reasoning_effort="low",
    )


async def record(provider: str, model: str | None, max_tokens: int, only: str | None) -> int:
    live = build_live_llm(provider, model, max_tokens)
    recorder = RecordingLLM(live, FIXTURES_DIR)
    failures = 0

    if only in (None, "ooda"):
        evidence = {
            "operator_present": True,
            "operator_confidence": 0.94,
            "vision_summary": SCENARIO_VISION.description,
            "change_ticket_valid": False,
            "change_ticket": None,
            "presence_known": True,
            "event_count": len(SCENARIO_EVENTS),
            "events": [
                {
                    "type": event.type.value,
                    "source": event.source.value,
                    "severity": event.severity.value,
                    "summary": event.summary,
                    "timestamp": event.timestamp.isoformat(),
                    **{k: v for k, v in (event.payload or {}).items() if k != "findings"},
                    "findings": (event.payload or {}).get("findings"),
                }
                for event in SCENARIO_EVENTS
            ],
        }
        messages = [
            {"role": "system", "content": OODA_SYSTEM_PROMPT},
            {"role": "user", "content": "Evidence bundle:\n" + json.dumps(evidence, indent=2)},
        ]
        try:
            payload, response = await recorder.complete_json(messages, task="ooda")
            print(f"[ooda] {response.model} in {response.latency_ms:.0f} ms -> {payload.get('classification')}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"[ooda] FAILED: {type(exc).__name__}: {exc}")

    if only in (None, "forensics"):
        engine = ForensicsEngine(recorder)
        try:
            report = await engine.analyze("inc_recording", SCENARIO_EVENTS, SCENARIO_VISION)
            print(
                f"[forensics] model={report.model} citations={len(report.citations)} "
                f"verified={report.citations_verified} recon_verified={report.recon_verified} "
                f"in {report.latency_ms:.0f} ms"
            )
            if not report.citations_verified:
                print("[forensics] warning: citations were not fully verified")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"[forensics] FAILED: {type(exc).__name__}: {exc}")

    print()
    print("fixtures in", FIXTURES_DIR)
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        print(f"  {path.name}: {path.stat().st_size} bytes")
    return failures


def list_fixtures() -> int:
    files = sorted(FIXTURES_DIR.glob("*.json"))
    if not files:
        print("no fixtures recorded yet")
        return 1
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"  {path.name}: CORRUPT")
            continue
        print(
            f"  {path.name}: model={data.get('model')} "
            f"latency={data.get('latency_ms')} task={data.get('task')}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["baseten", "meta", "fireworks"], default="baseten")
    parser.add_argument("--model", default=None)
    parser.add_argument("--max-tokens", type=int, default=3000)
    parser.add_argument("--only", choices=["ooda", "forensics"], default=None)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)

    if args.list:
        return list_fixtures()
    return asyncio.run(record(args.provider, args.model, args.max_tokens, args.only))


if __name__ == "__main__":
    raise SystemExit(main())
