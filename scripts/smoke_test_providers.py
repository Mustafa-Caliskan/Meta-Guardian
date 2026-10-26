"""Smoke-test Meta / Baseten / Fireworks endpoints and resolve real model IDs.

Usage:
    python scripts/smoke_test_providers.py            # list models, no probes
    python scripts/smoke_test_providers.py --probe    # tiny chat completion
    python scripts/smoke_test_providers.py --json     # machine-readable

Never prints API keys. Exit code is 0 when every *configured* provider answers
and every configured model ID exists on its provider (or when no key is set).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import (  # noqa: E402
    BASETEN_SPARK_OPEN_MODEL,
    GLIMMER_MODEL,
    META_SAM_MODEL,
    META_SPARK_MODEL,
    Settings,
    get_settings,
)


@dataclass
class ProviderCheck:
    name: str
    configured: bool
    reachable: bool = False
    status: str = ""
    models: list[str] | None = None
    expected_models: list[str] | None = None
    missing_models: list[str] | None = None
    probe_ok: bool | None = None
    probe_detail: str = ""
    error: str = ""


def _chat_probe(client: httpx.Client, base_url: str, headers: dict, model: str) -> tuple[bool, str]:
    try:
        response = client.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
                "max_tokens": 8,
                "temperature": 0,
            },
        )
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}: {response.text[:160]}"
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        return True, f"HTTP {response.status_code}: {str(text)[:80]!r}"
    except Exception as exc:  # noqa: BLE001 - smoke test wants every failure
        return False, f"{type(exc).__name__}: {exc}"


def check_provider(
    name: str,
    base_url: str,
    api_key: str,
    expected_models: list[str],
    *,
    probe: bool = False,
    timeout: float = 20.0,
) -> ProviderCheck:
    check = ProviderCheck(
        name=name,
        configured=bool(api_key),
        expected_models=list(expected_models),
    )
    if not api_key:
        check.status = "skipped (no API key)"
        return check

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=timeout) as client:
        try:
            response = client.get(f"{base_url}/models", headers=headers)
            check.status = f"HTTP {response.status_code}"
            check.reachable = response.status_code < 500
            if response.status_code == 200:
                payload = response.json()
                items = payload.get("data", payload if isinstance(payload, list) else [])
                check.models = sorted(
                    str(item.get("id", item)) if isinstance(item, dict) else str(item)
                    for item in items
                )
                check.missing_models = [
                    model for model in expected_models if model not in check.models
                ]
        except Exception as exc:  # noqa: BLE001
            check.error = f"{type(exc).__name__}: {exc}"
            check.status = "unreachable"
            return check

        if probe and expected_models:
            ok, detail = _chat_probe(client, base_url, headers, expected_models[0])
            check.probe_ok = ok
            check.probe_detail = detail

    return check


def build_checks(settings: Settings) -> list[ProviderCheck]:
    return [
        check_provider(
            "meta",
            settings.meta_base_url,
            settings.meta_api_key,
            [META_SPARK_MODEL, META_SAM_MODEL],
        ),
        check_provider(
            "baseten",
            settings.baseten_base_url,
            settings.baseten_api_key,
            [BASETEN_SPARK_OPEN_MODEL],
        ),
        check_provider(
            "fireworks",
            settings.fireworks_base_url,
            settings.fireworks_api_key,
            [GLIMMER_MODEL],
        ),
    ]


def summarize(checks: list[ProviderCheck], settings: Settings) -> tuple[int, list[str]]:
    configured = [c for c in checks if c.configured]
    failures: list[str] = []

    for check in configured:
        if not check.reachable:
            failures.append(f"{check.name}: unreachable ({check.error or check.status})")
        if check.missing_models:
            failures.append(
                f"{check.name}: model id(s) not advertised: {', '.join(check.missing_models)}"
            )
        if check.probe_ok is False:
            failures.append(f"{check.name}: probe failed ({check.probe_detail})")

    if not configured:
        return 0, ["no provider keys set - mock/replay mode only"]
    return (0 if not failures else 1), failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help="send a tiny completion")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(argv)

    settings = get_settings()
    checks = [
        check_provider(
            name,
            base_url,
            api_key,
            expected,
            probe=args.probe,
            timeout=args.timeout,
        )
        for name, base_url, api_key, expected in (
            (
                "meta",
                settings.meta_base_url,
                settings.meta_api_key,
                [META_SPARK_MODEL, META_SAM_MODEL],
            ),
            (
                "baseten",
                settings.baseten_base_url,
                settings.baseten_api_key,
                [settings.spark_open_model],
            ),
            (
                "fireworks",
                settings.fireworks_base_url,
                settings.fireworks_api_key,
                [settings.ooda_model],
            ),
        )
    ]

    code, notes = summarize(checks, settings)

    if args.json:
        print(
            json.dumps(
                {
                    "mode": settings.mode.value,
                    "routing": {
                        "ooda_model": settings.ooda_model,
                        "forensics_model": settings.forensics_model,
                        "code_model": settings.code_model,
                        "sam_model": settings.sam_model,
                        "spark_open_model": settings.spark_open_model,
                    },
                    "checks": [asdict(c) for c in checks],
                    "notes": notes,
                },
                indent=2,
            )
        )
    else:
        print(f"LLM_MODE = {settings.mode.value}")
        print(
            "routing: ooda={} forensics={} code={} sam={} spark_open={}".format(
                settings.ooda_model,
                settings.forensics_model,
                settings.code_model,
                settings.sam_model,
                settings.spark_open_model,
            )
        )
        print()
        for check in checks:
            print(f"[{check.name}] configured={check.configured} status={check.status}")
            if check.models is not None:
                preview = ", ".join(check.models[:12])
                suffix = " ..." if len(check.models) > 12 else ""
                print(f"  models: {preview}{suffix}")
            if check.missing_models:
                print(f"  MISSING: {', '.join(check.missing_models)}")
            if check.probe_ok is not None:
                print(f"  probe: {'ok' if check.probe_ok else 'FAIL'} ({check.probe_detail})")
            if check.error:
                print(f"  error: {check.error}")
        print()
        for note in notes:
            print(f"note: {note}")

    return code


if __name__ == "__main__":
    raise SystemExit(main())
