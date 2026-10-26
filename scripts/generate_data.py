"""Generate a realistic 30-day SIEM archive with a hidden reconnaissance trail.

The archive is synthetic but internally consistent:

* ~12,000 normal API log lines, mixed statuses, sessions, user agents, geos.
* An internal monitoring probe hitting ``/ops/scan`` hourly (benign noise that a
  naive detector would flag).
* A hidden reconnaissance burst from ``203.0.113.66`` exactly three days before
  the incident, followed by silence.
* The incident line itself (unauthenticated mass exfiltration, HTTP 200).

A manifest records the exact 1-based line numbers so every forensics citation
can be verified against the file. Nothing here is claimed to be real data.

Usage:
    python scripts/generate_data.py
    python scripts/generate_data.py --days 30 --seed 1337 --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.cloud.citations import verify_citations  # noqa: E402
from backend.config import HISTORY_LOGS_DIR, PROJECT_ROOT  # noqa: E402
from backend.models import Citation  # noqa: E402

LOG_FILENAME = "siem_30d.log"
MANIFEST_FILENAME = "siem_manifest.json"
ATTACKER_IP = "203.0.113.66"
MONITOR_IP = "10.0.0.50"
COMPROMISED_SESSION = "session-7f3a9c"

NORMAL_PATHS = [
    ("GET", "/api/v1/ops/flights", 200, 512),
    ("GET", "/api/v1/ops/flights", 200, 512),
    ("GET", "/api/v1/ops/data?aircraft=PC-1180&limit=10", 200, 2048),
    ("GET", "/api/v1/ops/data?aircraft=PC-2214&limit=10", 200, 2048),
    ("GET", "/api/v1/ops/data?aircraft=PC-3301&limit=5", 200, 1024),
    ("GET", "/health", 200, 64),
    ("POST", "/api/v1/admin/command", 401, 96),
    ("GET", "/api/v1/ops/scan", 404, 48),
    ("GET", "/api/v1/ops/data?aircraft=XX-0000&limit=10", 404, 48),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AviationOps/2.4",
    "Mozilla/5.0 (X11; Linux x86_64) AviationOps/2.4",
    "okhttp/4.12.0",
    "python-requests/2.32.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) OpsConsole/1.9",
]

INTERNAL_IPS = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.31"]
EXTERNAL_IPS = [
    "198.51.100.23",
    "198.51.100.77",
    "192.0.2.14",
    "192.0.2.88",
    "203.0.113.9",
    "203.0.113.41",
]
GEOS = ["TR", "DE", "NL", "FR", "GB", "US", "AE"]


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_line(
    moment: datetime,
    ip: str,
    method: str,
    path: str,
    status: int,
    size: int,
    latency: int,
    ua: str,
    geo: str,
    session: str = "-",
) -> str:
    return (
        f"{iso(moment)} src={ip} dst=10.0.0.12 method={method} path={path} "
        f"status={status} bytes={size} latency_ms={latency} "
        f'session={session} geo={geo} ua="{ua}"'
    )


def build_archive(
    *,
    days: int = 30,
    seed: int = 1337,
    end: datetime | None = None,
    out_dir: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    rng = random.Random(seed)
    end = (end or datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)).astimezone(
        timezone.utc
    )
    start = end - timedelta(days=days)

    rows: list[dict[str, Any]] = []

    def add(moment: datetime, line: str, tag: str | None = None, meta: dict | None = None) -> None:
        rows.append({"moment": moment, "line": line, "tag": tag, "meta": meta or {}})

    # --- normal operational traffic -----------------------------------------
    day = start
    while day < end:
        count = rng.randint(340, 460)
        for _ in range(count):
            offset = timedelta(
                seconds=rng.randint(0, 86399), microseconds=rng.randint(0, 999_999)
            )
            moment = day + offset
            if moment >= end:
                continue
            method, path, status, size = rng.choice(NORMAL_PATHS)
            internal = rng.random() < 0.72
            ip = rng.choice(INTERNAL_IPS) if internal else rng.choice(EXTERNAL_IPS)
            geo = "TR" if internal else rng.choice(GEOS)
            ua = rng.choice(USER_AGENTS)
            session = "-"
            if internal and status == 200 and "data" in path:
                session = rng.choice(["session-ops-valid", "session-7f3a9c"])
            elif path.startswith("/api/v1/admin"):
                session = rng.choice(["-", "session-ops-valid"])
            add(
                moment,
                format_line(
                    moment,
                    ip,
                    method,
                    path,
                    status,
                    size,
                    rng.randint(4, 180),
                    ua,
                    geo,
                    session,
                ),
            )
        day += timedelta(days=1)

    # --- benign internal monitoring probe (hourly) ---------------------------
    probe = start
    while probe < end:
        add(
            probe,
            format_line(
                probe,
                MONITOR_IP,
                "GET",
                "/api/v1/ops/scan",
                200,
                320,
                8,
                "InternalMonitor/1.0 (+soc)",
                "TR",
                "session-ops-valid",
            ),
            tag="benign",
            meta={"reason": "hourly internal monitoring probe"},
        )
        probe += timedelta(hours=1)

    # --- hidden reconnaissance, exactly 3 days before the incident ----------
    recon_start = end - timedelta(days=3, minutes=17)
    recon_steps = [
        ("GET", "/api/v1/ops/scan", 200, 320, 0),
        ("GET", "/api/v1/ops/flights", 200, 512, 6),
        ("GET", "/api/v1/ops/data?aircraft=PC-1180&limit=50", 200, 10240, 11),
        ("POST", "/api/v1/admin/command", 401, 96, 19),
        ("GET", "/api/v1/ops/data?aircraft=ALL&limit=5", 200, 1024, 27),
        ("GET", "/api/v1/ops/data?aircraft=ALL&limit=5", 200, 1024, 41),
        ("GET", "/api/v1/ops/scan", 200, 320, 55),
    ]
    for method, path, status, size, offset_seconds in recon_steps:
        moment = recon_start + timedelta(seconds=offset_seconds)
        add(
            moment,
            format_line(
                moment,
                ATTACKER_IP,
                method,
                path,
                status,
                size,
                rng.randint(20, 90),
                "python-requests/2.32.3",
                "RU",
                "-" if "admin" in path else COMPROMISED_SESSION,
            ),
            tag="recon",
            meta={"path": path, "status": status, "method": method},
        )

    # --- the incident: unauthenticated mass exfiltration ---------------------
    incident_moment = end - timedelta(minutes=2)
    incident_path = "/api/v1/ops/data?aircraft=ALL&limit=99999"
    add(
        incident_moment,
        format_line(
            incident_moment,
            ATTACKER_IP,
            "GET",
            incident_path,
            200,
            1_843_200,
            63,
            "python-requests/2.32.3",
            "RU",
            COMPROMISED_SESSION,
        ),
        tag="incident",
        meta={"path": incident_path, "status": 200, "method": "GET"},
    )

    rows.sort(key=lambda row: row["moment"])
    lines = [row["line"] for row in rows]

    by_tag: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, row in enumerate(rows, start=1):
        if row["tag"]:
            by_tag.setdefault(row["tag"], []).append((index, row))

    recon_entries = [
        {
            "line": index,
            "timestamp": iso(row["moment"]),
            "method": row["meta"]["method"],
            "path": row["meta"]["path"],
            "status": row["meta"]["status"],
        }
        for index, row in by_tag.get("recon", [])
    ]
    incident_index, incident_row = by_tag["incident"][0]
    benign_sample = [
        {"line": index, "timestamp": iso(row["moment"]), "path": "/api/v1/ops/scan"}
        for index, row in by_tag.get("benign", [])[:5]
    ]

    log_path = (out_dir or HISTORY_LOGS_DIR) / LOG_FILENAME
    try:
        log_rel = log_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        log_rel = str(log_path.resolve())
    log_text = "\n".join(lines) + "\n"
    digest = hashlib.sha256(log_text.encode("utf-8")).hexdigest()

    manifest: dict[str, Any] = {
        "version": 1,
        "seed": seed,
        "days": days,
        "start": iso(start),
        "end": iso(end),
        "log_file": log_rel,
        "total_lines": len(lines),
        "sha256": digest,
        "attacker_ip": ATTACKER_IP,
        "compromised_session": COMPROMISED_SESSION,
        "search_terms": [
            ATTACKER_IP,
            "/api/v1/ops/scan",
            "aircraft=ALL",
            COMPROMISED_SESSION,
        ],
        "recon": {
            "ip": ATTACKER_IP,
            "first_line": recon_entries[0]["line"],
            "first_timestamp": recon_entries[0]["timestamp"],
            "lines": recon_entries,
            "citation": {
                "log_file": log_rel,
                "line": recon_entries[0]["line"],
                "excerpt": f"src={ATTACKER_IP} dst=10.0.0.12 method=GET path=/api/v1/ops/scan status=200",
            },
        },
        "incident": {
            "ip": ATTACKER_IP,
            "line": incident_index,
            "timestamp": iso(incident_row["moment"]),
            "path": incident_path,
            "status": 200,
            "citation": {
                "log_file": log_rel,
                "line": incident_index,
                "excerpt": f"src={ATTACKER_IP} dst=10.0.0.12 method=GET path={incident_path} status=200",
            },
        },
        "benign": {
            "note": "Internal hourly monitoring probe - must not be treated as an attack.",
            "ip": MONITOR_IP,
            "sample_lines": benign_sample,
        },
    }

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(log_text, encoding="utf-8")
    (log_path.parent / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return lines, manifest


def verify_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    citations = [
        Citation(**manifest["recon"]["citation"]),
        Citation(**manifest["incident"]["citation"]),
    ]
    checks = verify_citations(citations, PROJECT_ROOT)
    return [check.model_dump() for check in checks]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--end", help="ISO timestamp, default: current UTC hour")
    parser.add_argument("--no-verify", action="store_true")
    args = parser.parse_args(argv)

    end = (
        datetime.fromisoformat(args.end.replace("Z", "+00:00"))
        if args.end
        else None
    )
    lines, manifest = build_archive(days=args.days, seed=args.seed, end=end)

    print(f"wrote {manifest['log_file']} ({len(lines)} lines)")
    print(f"sha256: {manifest['sha256']}")
    print(f"recon line: {manifest['recon']['first_line']} @ {manifest['recon']['first_timestamp']}")
    print(f"incident line: {manifest['incident']['line']} @ {manifest['incident']['timestamp']}")

    if not args.no_verify:
        checks = verify_manifest(manifest)
        for check in checks:
            status = "OK" if check["exists"] and check["excerpt_matches"] else "FAIL"
            print(f"citation {status}: {check['citation']['log_file']}:{check['citation']['line']} {check['detail']}")
        if not all(c["exists"] and c["excerpt_matches"] for c in checks):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
