"""Sanitize evidence before it leaves the edge host.

The camera frame never goes to the cloud. Only a text bundle does, and that
bundle is stripped of local absolute paths, usernames, session tokens and
anything that looks like a secret. This keeps the privacy story honest and
shrinks the 1M-context payload.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models import SecurityEvent, VisionEvidence

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
]
USER_PATH = re.compile(r"([A-Za-z]:[\\/]Users[\\/][^\\/]+|/home/[^/]+)", re.IGNORECASE)
SESSION_PATTERN = re.compile(r"^session-[A-Za-z0-9\-_]+$")


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_paths(text: str) -> str:
    """Remove the user profile from any free-text field."""
    return USER_PATH.sub("~", text)


def safe_path(raw: str | None) -> str | None:
    """Keep only the last two path components; drop the user profile."""
    if not raw:
        return None
    cleaned = USER_PATH.sub("~", str(raw)).replace("\\", "/")
    parts = [part for part in cleaned.split("/") if part and part not in ("~",)]
    return "/".join(parts[-2:]) if parts else None


def mask_session(token: Any) -> str:
    if token in (None, "", "-", "unknown"):
        return "none"
    text = str(token)
    if len(text) <= 8:
        return "session-***"
    return f"{text[:8]}***"


def sanitize_event(event: SecurityEvent) -> dict[str, Any]:
    payload = event.payload or {}
    sanitized: dict[str, Any] = {
        "type": event.type.value,
        "source": event.source.value,
        "severity": event.severity.value,
        "summary": redact_paths(redact_secrets(event.summary))[:300],
        "timestamp": event.timestamp.isoformat(),
    }

    for key in ("ip", "method", "path", "query", "status"):
        if key in payload:
            sanitized[key] = redact_secrets(str(payload[key]))[:200]

    if payload.get("session"):
        sanitized["session"] = mask_session(payload["session"])

    if payload.get("mountpoint"):
        sanitized["mountpoint"] = safe_path(payload["mountpoint"])

    findings = payload.get("findings") or []
    if findings:
        sanitized["findings"] = [
            {
                "name": str(item.get("name", ""))[:80],
                "extension": str(item.get("extension", ""))[:12],
                "size": item.get("size"),
                "sha256": str(item.get("sha256", ""))[:16],
            }
            for item in findings[:5]
        ]

    return sanitized


def sanitize_vision(vision: VisionEvidence | None) -> dict[str, Any]:
    if vision is None:
        return {"available": False}
    return {
        "available": True,
        "operator_present": vision.operator_present,
        "presence_known": vision.presence_known,
        "confidence": vision.confidence,
        "roi": vision.roi,
        "motion_ratio": vision.motion_ratio,
        "method": vision.method,
        "description": redact_secrets(vision.description)[:400],
        "frame_sent_to_cloud": False,
    }


def sanitize_bundle(
    events: list[SecurityEvent], vision: VisionEvidence | None = None
) -> dict[str, Any]:
    return {
        "event_count": len(events),
        "events": [sanitize_event(event) for event in events[:40]],
        "vision": sanitize_vision(vision),
        "note": "sanitized at the edge: no image bytes, no user paths, secrets redacted",
    }


__all__ = [
    "redact_secrets",
    "safe_path",
    "mask_session",
    "sanitize_event",
    "sanitize_vision",
    "sanitize_bundle",
]
