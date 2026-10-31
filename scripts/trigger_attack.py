"""Fire a real attack at the protected service and watch Meta-Guardian react.

This is the script that closes the demo loop: it does **not** call
``/api/simulate``. It sends real HTTP requests to the target on port 8001; the
control center's ``NetWatcher`` tails the audit log, the correlator bundles the
events and the OODA agent runs on its own.

Examples
--------
    # real unauthenticated exfiltration (HTTP 200), then wait for containment
    python scripts/trigger_attack.py --exfil --watch

    # spoof the attacker IP through a trusted proxy header (TRUST_FORWARDED_FOR=1)
    python scripts/trigger_attack.py --exfil --xff 203.0.113.66 --watch

    # run the full chain: attack -> containment -> forensics -> patch (200 -> 403)
    python scripts/trigger_attack.py --exfil --watch --patch

    # copy a payload onto a real mounted USB stick (path you provide)
    python scripts/trigger_attack.py --usb E:\\
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import get_settings  # noqa: E402

EXFIL_PATH = "/api/v1/ops/data"
EXFIL_PARAMS = {"aircraft": "ALL", "limit": 99999}

settings = get_settings()


def _cockpit_headers(settings) -> dict[str, str]:
    """Bearer header for the control plane when MG_COCKPIT_TOKEN is configured."""
    if getattr(settings, "cockpit_auth_enabled", False):
        return {"Authorization": f"Bearer {settings.cockpit_token}"}
    return {}


def _client(base_url: str, timeout: float = 15.0) -> httpx.Client:
    return httpx.Client(base_url=base_url, timeout=timeout)


def reset_target(base_url: str, token: str) -> None:
    headers = {"x-internal-token": token} if token else {}
    with _client(base_url) as client:
        try:
            client.post("/internal/reset", headers=headers)
            print("[target] reset to vulnerable state")
        except httpx.HTTPError as exc:
            print(f"[target] reset failed (continuing): {exc}")


def send_exfil(base_url: str, xff: str | None) -> int:
    headers = {"x-forwarded-for": xff} if xff else {}
    with _client(base_url) as client:
        response = client.get(EXFIL_PATH, params=EXFIL_PARAMS, headers=headers)
        leaked = response.json().get("count") if response.headers.get(
            "content-type", ""
        ).startswith("application/json") else "?"
        print(
            f"[attack] GET {EXFIL_PATH}?aircraft=ALL -> HTTP {response.status_code} "
            f"(records={leaked})"
        )
        return response.status_code


def send_admin(base_url: str, xff: str | None) -> int:
    headers = {"x-forwarded-for": xff} if xff else {}
    with _client(base_url) as client:
        response = client.post(
            "/api/v1/admin/command",
            json={"command": "dump core-db", "target": "ops-core"},
            headers=headers,
        )
        print(f"[attack] POST /api/v1/admin/command -> HTTP {response.status_code}")
        return response.status_code


def drop_usb_payload(drive: str) -> Path:
    target = Path(drive)
    if not target.is_dir():
        raise SystemExit(f"USB path is not a directory: {target}")
    payload = target / "payload.ps1"
    payload.write_text(
        "# unsigned payload staged by trigger_attack.py (does not auto-run)\n"
        "Write-Host 'Meta-Guardian demo payload'\n",
        encoding="utf-8",
    )
    print(f"[usb] wrote {payload} ({payload.stat().st_size} bytes, autorun disabled)")
    return payload


def wait_for_incident(
    control_url: str, known_ids: set[str], timeout: float
) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with _client(control_url, timeout=5) as client:
                body = client.get(
                    "/api/incidents", headers=_cockpit_headers(settings)
                ).json()
                for incident in body.get("incidents", []):
                    if incident["id"] not in known_ids:
                        return incident
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    return None


def current_incident_ids(control_url: str) -> set[str]:
    try:
        with _client(control_url, timeout=5) as client:
            body = client.get(
                "/api/incidents", headers=_cockpit_headers(settings)
            ).json()
            return {incident["id"] for incident in body.get("incidents", [])}
    except httpx.HTTPError as exc:
        print(f"[control] cannot reach {control_url}: {exc}")
        return set()


def patch_incident(control_url: str, incident_id: str) -> dict | None:
    try:
        with _client(control_url, timeout=180) as client:
            response = client.post(
                f"/api/incidents/{incident_id}/patch",
                headers=_cockpit_headers(settings),
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        print(f"[patch] failed: {exc}")
        return None


def print_incident(incident: dict) -> None:
    decision = incident.get("decision") or {}
    policy = incident.get("policy") or {}
    vision = incident.get("vision") or {}
    print("\n[incident]", incident.get("id"), "scenario", incident.get("scenario"))
    print("  status        :", incident.get("status"))
    print("  classification:", decision.get("classification"), f"(conf {decision.get('confidence')})")
    print("  policy mode   :", policy.get("mode"), "|", policy.get("reason", "")[:120])
    print(
        "  vision        :",
        f"present={vision.get('operator_present')} conf={vision.get('confidence')} "
        f"method={vision.get('method')} motion={vision.get('motion_ratio')}",
    )
    for result in incident.get("action_results") or []:
        mark = "OK  " if result.get("success") else "FAIL"
        print(f"  [{mark}] {result.get('action')} -> {result.get('target')}")

    patch = incident.get("patch")
    if patch:
        print(
            "  patch         :",
            f"{patch.get('rule_id')} fingerprint={patch.get('rule_fingerprint')} "
            f"HTTP {patch.get('before_status')} -> {patch.get('after_status')} "
            f"verified={patch.get('verified')}",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=None, help="target base URL (default from settings)")
    parser.add_argument("--control", default=None, help="control center URL")
    parser.add_argument("--exfil", action="store_true", help="send the exfiltration request")
    parser.add_argument("--admin", action="store_true", help="send a privileged admin command")
    parser.add_argument("--xff", default=None, help="X-Forwarded-For value (proxy trust required)")
    parser.add_argument("--usb", default=None, help="copy a payload onto this mounted drive")
    parser.add_argument("--watch", action="store_true", help="wait for an incident to appear")
    parser.add_argument("--patch", action="store_true", help="run forensics + patch after containment")
    parser.add_argument("--reset", action="store_true", help="reset the target before attacking")
    parser.add_argument("--timeout", type=float, default=45.0, help="watch timeout seconds")
    args = parser.parse_args(argv)

    target = (args.target or settings.target_base_url).rstrip("/")
    control = (args.control or f"http://{settings.host}:{settings.port}").rstrip("/")

    if not any([args.exfil, args.admin, args.usb]):
        parser.error("choose at least one action: --exfil, --admin or --usb")

    if args.reset:
        reset_target(target, settings.internal_api_token)

    known = current_incident_ids(control) if args.watch else set()

    if args.usb:
        drop_usb_payload(args.usb)

    xff = args.xff
    if xff is None and getattr(settings, "trust_forwarded_for", False):
        # Mirrors the cockpit's fire_attack: when the deployment opted into
        # trusting X-Forwarded-For, the demo attacker IP is used so the gateway
        # has a blockable, non-infrastructure address. Without this the only
        # source is the container/host address, which is protected and therefore
        # never blocked, and the run ends with "no containment action proposed".
        xff = settings.demo_attacker_ip
        print(f"[attack] using X-Forwarded-For {xff} (TRUST_FORWARDED_FOR=1)")

    statuses: list[int] = []
    if args.exfil:
        statuses.append(send_exfil(target, xff))
    if args.admin:
        statuses.append(send_admin(target, xff))

    if args.watch:
        print(f"[watch] waiting up to {args.timeout:.0f}s for a new incident…")
        incident = wait_for_incident(control, known, args.timeout)
        if incident is None:
            print("[watch] no incident yet. Is `python -m backend.main` running with watchers?")
            return 2
        print_incident(incident)

        if args.patch:
            patched = patch_incident(control, incident["id"])
            if patched:
                print_incident(patched)
                patch = patched.get("patch") or {}
                if patch.get("verified"):
                    print("\n[RESULT] PATCH VERIFIED: HTTP 200 -> HTTP 403")
                else:
                    print("\n[RESULT] patch not verified:", patch.get("verification_note"))
                    return 3

    print("\n[log] target audit tail:")
    with _client(target) as client:
        try:
            headers = (
                {"x-internal-token": settings.internal_api_token}
                if settings.internal_api_token
                else {}
            )
            entries = client.get(
                "/internal/requests", params={"limit": 5}, headers=headers
            ).json()["requests"]
        except Exception:  # noqa: BLE001
            entries = []
    for entry in entries[-5:]:
        print(" ", json.dumps(entry, ensure_ascii=False)[:240])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
