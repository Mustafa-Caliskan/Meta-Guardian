"""Case file export: a forensic artefact, not a UI screenshot.

Two formats, one source of truth:

* ``json``     — machine-readable, mirrors the incident schema plus derived fields
* ``markdown`` — a readable SOC case report for a reviewer or a jury

Everything here is derived from the stored ``Incident``. Nothing is invented: if
the patcher never ran, the patch section says so; if presence was unknown, the
report says unknown.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (Incident, IncidentStatus, PolicyMode, utc_now)

SCHEMA_VERSION = "1.0"
LEDGER_FILENAME = "hashchain.jsonl"


def canonical_incident_json(incident: Incident) -> str:
    """Deterministic JSON of the stored incident.

    Sorted keys and fixed separators mean the same incident always hashes the
    same way, on any machine. Frames are referenced by path only, never embedded,
    so deleting an expired frame does not invalidate the record of the incident.
    """
    payload = incident.model_dump(mode="json")
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def incident_content_hash(incident: Incident) -> str:
    return hashlib.sha256(
        canonical_incident_json(incident).encode("utf-8")
    ).hexdigest()


class IncidentLedger:
    """Append-only hash chain over every persisted incident revision.

    The chain is written from ``_persist``, not from case-file rendering: an
    approval legitimately mutates the incident, so hashing at export time would
    report a false "tampered" on the next read. Every write appends a new row
    whose ``prev_sha256`` is the previous row's content hash.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _read(self) -> list[tuple[int, dict[str, Any]]]:
        if not self.path.is_file():
            return []
        records: list[tuple[int, dict[str, Any]]] = []
        for lineno, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            records.append((lineno, json.loads(line)))
        return records

    def append(self, incident: Incident, *, kind: str | None = None) -> dict[str, Any]:
        try:
            records = self._read()
        except (OSError, json.JSONDecodeError):
            records = []
        previous = records[-1][1].get("content_sha256", "") if records else ""
        if kind is None:
            seen = any(rec.get("incident_id") == incident.id for _, rec in records)
            kind = "updated" if seen else "created"
        entry = {
            "incident_id": incident.id,
            "content_sha256": incident_content_hash(incident),
            "prev_sha256": previous,
            "recorded_at": utc_now().isoformat(),
            "kind": kind,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
                )
        except OSError:
            return entry
        return entry

    def verify(self, incident: Incident) -> dict[str, Any]:
        """Compare the current incident against its last ledger row.

        ``chain_valid`` is ``None`` when there is nothing to verify against (the
        incident was never persisted, or persistence is disabled). Reporting
        "not recorded" is honest; reporting "tampered" would not be.
        """
        result: dict[str, Any] = {
            "chain_valid": None,
            "expected_sha256": None,
            "actual_sha256": incident_content_hash(incident),
            "records": 0,
            "broken_at_line": None,
            "broken_reason": "",
        }
        if not self.path.is_file():
            result["broken_reason"] = "no integrity ledger on disk"
            return result

        try:
            records = self._read()
        except (OSError, json.JSONDecodeError) as exc:
            result["chain_valid"] = False
            result["broken_reason"] = f"ledger is unreadable: {exc}"
            return result

        result["records"] = len(records)
        previous = ""
        for lineno, record in records:
            if record.get("prev_sha256", "") != previous:
                result["chain_valid"] = False
                result["broken_at_line"] = lineno
                result["broken_reason"] = f"ledger link broken at line {lineno}"
                return result
            previous = record.get("content_sha256", "")

        mine = [
            (lineno, record)
            for lineno, record in records
            if record.get("incident_id") == incident.id
        ]
        if not mine:
            result["broken_reason"] = "no ledger record for this incident"
            return result

        lineno, last = mine[-1]
        result["expected_sha256"] = last.get("content_sha256")
        result["chain_valid"] = result["expected_sha256"] == result["actual_sha256"]
        if not result["chain_valid"]:
            result["broken_at_line"] = lineno
            result["broken_reason"] = (
                "incident content differs from the last recorded hash"
            )
        return result


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).name


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value < 1000:
        return f"{value:.0f} ms"
    return f"{value / 1000:.2f} s"


def _bool(value: bool | None) -> str:
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def incident_timings(incident: Incident) -> dict[str, float | None]:
    """Derive MTTD / MTTR / patch latency from recorded timestamps."""
    mttd: float | None = None
    if incident.decision and incident.events:
        first = min(event.timestamp for event in incident.events)
        mttd = max(0.0, (incident.decision.created_at - first).total_seconds() * 1000)

    mttr: float | None = None
    results = incident.action_results or []
    if incident.decision and results:
        last = max(result.executed_at for result in results)
        mttr = max(0.0, (last - incident.decision.created_at).total_seconds() * 1000)

    return {"mttd_ms": mttd, "mttr_ms": mttr}


def _human_decision(incident: Incident) -> dict[str, Any] | None:
    """Who acted on this incident, when, and why.

    Returns None when no human touched it: an automatic containment is an
    automatic containment, and the report must not invent an approver.
    """
    policy = incident.policy
    decided_by = incident.decided_by
    decided_at = incident.decided_at
    note = incident.decision_note

    if decided_by is None and policy is not None:
        decided_by = policy.approved_by or policy.rejected_by
        decided_at = policy.approved_at or policy.rejected_at
        note = note or policy.rejection_reason

    if decided_by is None:
        return None

    if policy is not None and policy.rejected_by:
        action = "rejected"
        reason = policy.rejection_reason
    elif policy is not None and policy.approved_by:
        action = "approved"
        reason = ""
    else:
        action = "dismissed"
        reason = ""

    return {
        "action": action,
        "operator": decided_by,
        "at": _iso(decided_at),
        "reason": reason,
        "note": note,
    }


def build_casefile(
    incident: Incident, *, integrity: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Canonical dict used by both the JSON response and the Markdown renderer."""
    decision = incident.decision
    policy = incident.policy
    vision = incident.vision
    forensics = incident.forensics
    patch = incident.patch
    timings = incident_timings(incident)

    events = [
        {
            "id": event.id,
            "timestamp": _iso(event.timestamp),
            "source": event.source.value,
            "type": event.type.value,
            "severity": event.severity.value,
            "summary": event.summary,
            "payload": event.payload,
        }
        for event in incident.events
    ]

    actions = [
        {
            "action": result.action.value,
            "target": result.target,
            "success": result.success,
            "detail": result.detail,
            "executed_at": _iso(result.executed_at),
        }
        for result in (incident.action_results or [])
    ]

    citations = []
    if forensics:
        citations = [
            {
                "log_file": citation.log_file,
                "line": citation.line,
                "excerpt": citation.excerpt,
            }
            for citation in forensics.citations
        ]

    patch_block: dict[str, Any] | None = None
    if patch:
        patch_block = {
            "applied": patch.applied,
            "verified": patch.verified,
            "before_status": patch.before_status,
            "after_status": patch.after_status,
            "rule_id": patch.rule_id,
            "rule_fingerprint": patch.rule_fingerprint,
            "rolled_back": patch.rolled_back,
            "target_file": patch.target_file,
            "model": patch.model,
            "latency_ms": patch.latency_ms,
            "verification_note": patch.verification_note,
            "created_at": _iso(patch.created_at),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "attack_techniques": incident.attack_techniques,
        "incident": {
            "id": incident.id,
            "scenario": incident.scenario,
            "status": incident.status.value,
            "created_at": _iso(incident.created_at),
            "updated_at": _iso(incident.updated_at),
            "generated_at": _iso(incident.touch().updated_at),
        },
        "timings": {
            "mttd_ms": None if timings["mttd_ms"] is None else round(timings["mttd_ms"], 2),
            "mttr_ms": None if timings["mttr_ms"] is None else round(timings["mttr_ms"], 2),
            "patch_latency_ms": None if patch is None else round(patch.latency_ms, 2),
        },
        "events": events,
        "vision": (
            {
                "operator_present": vision.operator_present,
                "presence_known": vision.presence_known,
                "confidence": vision.confidence,
                "roi": vision.roi,
                "motion_ratio": vision.motion_ratio,
                "method": vision.method,
                "model": vision.model,
                "description": vision.description,
                "frame_file": _basename(vision.frame_path),
                "mask_file": _basename(vision.mask_path),
                "frame_source": vision.frame_source,
                "tampered": vision.tampered,
                "tamper_reason": vision.tamper_reason,
                "frame_mean": vision.frame_mean,
                "frame_stddev": vision.frame_stddev,
            }
            if vision
            else None
        ),
        "decision": (
            {
                "classification": decision.classification.value,
                "severity": decision.severity.value,
                "confidence": decision.confidence,
                "reasoning": decision.reasoning,
                "evidence_summary": decision.evidence_summary,
                "model": decision.model,
                "latency_ms": decision.latency_ms,
                "created_at": _iso(decision.created_at),
                "proposed_actions": [
                    {
                        "action": action.action.value,
                        "target": action.target,
                        "reason": action.reason,
                    }
                    for action in decision.actions
                ],
            }
            if decision
            else None
        ),
        "policy": (
            {
                "mode": policy.mode.value,
                "classification": policy.classification.value,
                "severity": policy.severity.value,
                "confidence": policy.confidence,
                "reason": policy.reason,
                "ticket_id": policy.ticket_id,
                "operator_present": policy.operator_present,
                "evaluated_at": _iso(policy.evaluated_at),
                "approved_count": len(policy.approved_actions),
                "pending_count": len(policy.pending_actions),
                "rate_limited_count": len(policy.rate_limited_actions),
                "ticket_owner_match": policy.ticket_owner_match,
                "session": {
                    "owner": policy.session_owner,
                    "role": policy.session_role,
                    "origin_ip": policy.session_origin_ip,
                },
            }
            if policy
            else None
        ),
        "human_decision": _human_decision(incident),
        "integrity": integrity,
        "mcp_actions": actions,
        "forensics": (
            {
                "model": forensics.model,
                "summary": forensics.summary,
                "earliest_discovery": _iso(forensics.earliest_discovery),
                "attack_chain": [
                    {
                        "timestamp": _iso(step.timestamp),
                        "source_ip": step.source_ip,
                        "endpoint": step.endpoint,
                        "description": step.description,
                    }
                    for step in forensics.attack_chain
                ],
                "vulnerable_file": forensics.vulnerable_file,
                "vulnerable_line": forensics.vulnerable_line,
                "vulnerable_code": forensics.vulnerable_code,
                "citations": citations,
                "citations_verified": forensics.citations_verified,
                "recon_verified": forensics.recon_verified,
                "archive_lines_scanned": forensics.archive_lines_scanned,
                "input_tokens": forensics.input_tokens,
                "latency_ms": forensics.latency_ms,
            }
            if forensics
            else None
        ),
        "patch": patch_block,
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _cell(value: Any) -> str:
    text = "n/a" if value is None or value == "" else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(casefile: dict[str, Any]) -> str:
    inc = casefile["incident"]
    timings = casefile["timings"]
    vision = casefile["vision"]
    decision = casefile["decision"]
    policy = casefile["policy"]
    forensics = casefile["forensics"]
    patch = casefile["patch"]

    lines: list[str] = [
        f"# SOC Case File — {inc['id']}",
        "",
        f"**Scenario:** {inc['scenario']}  ",
        f"**Status:** `{inc['status']}`  ",
        f"**Detected:** {inc['created_at']}  ",
        f"**Exported:** {inc['generated_at']}  ",
        f"**Schema:** {casefile['schema_version']}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Time to detect (MTTD) | {_cell(_fmt_ms(timings['mttd_ms']))} |",
        f"| Time to contain (MTTR) | {_cell(_fmt_ms(timings['mttr_ms']))} |",
        f"| Patch + verification | {_cell(_fmt_ms(timings['patch_latency_ms']))} |",
        f"| Events correlated | {len(casefile['events'])} |",
        f"| MCP actions | {len(casefile['mcp_actions'])} |",
        f"| Classification | {_cell((decision or {}).get('classification'))} |",
        f"| Policy mode | {_cell((policy or {}).get('mode'))} |",
        f"| Patch verified | {_cell(_bool((patch or {}).get('verified')))} |",
        "",
    ]

    lines += ["## Correlated events", ""]
    if casefile["events"]:
        lines += [
            "| Timestamp | Source | Type | Severity | Summary |",
            "|---|---|---|---|---|",
        ]
        for event in casefile["events"]:
            lines.append(
                "| {ts} | {src} | {typ} | {sev} | {sum} |".format(
                    ts=_cell(event["timestamp"]),
                    src=_cell(event["source"]),
                    typ=_cell(event["type"]),
                    sev=_cell(event["severity"]),
                    sum=_cell(event["summary"]),
                )
            )
    else:
        lines.append("_No events recorded._")
    lines.append("")

    lines += ["## Physical evidence", ""]
    if vision:
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Operator present | {_cell(_bool(vision['operator_present']))} |",
            f"| Presence known | {_cell(_bool(vision['presence_known']))} |",
            f"| Confidence | {vision['confidence']:.3f} |",
            f"| ROI (x, y, w, h) | {_cell(vision['roi'])} |",
            f"| Motion ratio | {vision['motion_ratio']:.4f} |",
            f"| Method | {_cell(vision['method'])} |",
            f"| Segmentation model | {_cell(vision['model'])} |",
            f"| Frame source | {_cell(vision['frame_source'])} |",
            f"| Frame file | {_cell(vision['frame_file'])} |",
            f"| Mask file | {_cell(vision['mask_file'])} |",
            f"| Camera tampered | {_cell(_bool(vision.get('tampered')))} |",
            f"| Tamper reason | {_cell(vision.get('tamper_reason') or 'n/a')} |",
            "",
            f"> {vision['description']}",
            "",
        ]
    else:
        lines += ["_No camera evidence for this incident._", ""]

    lines += ["## OODA decision", ""]
    if decision:
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Classification | `{_cell(decision['classification'])}` |",
            f"| Severity | {_cell(decision['severity'])} |",
            f"| Confidence | {decision['confidence']:.3f} |",
            f"| Model | {_cell(decision['model'])} |",
            f"| Latency | {_cell(_fmt_ms(decision['latency_ms']))} |",
            f"| Decided at | {_cell(decision['created_at'])} |",
            "",
            f"**Reasoning:** {decision['reasoning'] or 'n/a'}",
            "",
        ]
        if decision["proposed_actions"]:
            lines += ["| Proposed action | Target | Reason |", "|---|---|---|"]
            for action in decision["proposed_actions"]:
                lines.append(
                    f"| {_cell(action['action'])} | {_cell(action['target'])} | {_cell(action['reason'])} |"
                )
            lines.append("")
    else:
        lines += ["_No decision recorded._", ""]

    lines += ["## MITRE ATT&CK", ""]
    techniques = casefile.get("attack_techniques") or []
    if techniques:
        lines += ["| Technique | Name |", "|---|---|"]
        for technique in techniques:
            lines.append(f"| `{_cell(technique['id'])}` | {_cell(technique['name'])} |")
        lines += [
            "",
            "_Techniques describe the activity in this incident. For a benign verdict "
            "they are the activity that was evaluated and cleared, not a confirmed attack._",
            "",
        ]
    else:
        lines += ["_No technique mapped._", ""]

    lines += ["## Policy gate", ""]
    if policy:
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Mode | `{_cell(policy['mode'])}` |",
            f"| Reason | {_cell(policy['reason'])} |",
            f"| Change ticket | {_cell(policy['ticket_id'])} |",
            f"| Session | {_cell((policy.get('session') or {}).get('owner'))} / "
            f"{_cell((policy.get('session') or {}).get('role'))} / "
            f"origin {_cell((policy.get('session') or {}).get('origin_ip'))} |",
            f"| Approved / pending / limited | {policy['approved_count']} / {policy['pending_count']} / {policy['rate_limited_count']} |",
            "",
        ]
    else:
        lines += ["_No policy verdict recorded._", ""]

    lines += ["## Human decision", ""]
    human = casefile["human_decision"]
    if human:
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Action | `{_cell(human['action'])}` |",
            f"| Operator | {_cell(human['operator'])} |",
            f"| At | {_cell(human['at'])} |",
            f"| Reason | {_cell(human['reason'] or 'n/a')} |",
            "",
        ]
        if human["note"] and human["note"] != human["reason"]:
            lines += [f"> {human['note']}", ""]
    else:
        lines += [
            "_No human decision: this incident was handled by the deterministic gate._",
            "",
        ]

    lines += ["## Containment actions (MCP)", ""]
    if casefile["mcp_actions"]:
        lines += ["| Action | Target | Result | Detail | Executed |", "|---|---|---|---|---|"]
        for action in casefile["mcp_actions"]:
            lines.append(
                "| {act} | {tgt} | {res} | {det} | {ts} |".format(
                    act=_cell(action["action"]),
                    tgt=_cell(action["target"]),
                    res=_cell("OK" if action["success"] else "FAILED"),
                    det=_cell(action["detail"]),
                    ts=_cell(action["executed_at"]),
                )
            )
    else:
        lines.append("_No containment action was executed._")
    lines.append("")

    lines += ["## Cloud forensics", ""]
    if forensics:
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Model | {_cell(forensics['model'])} |",
            f"| Earliest discovery | {_cell(forensics['earliest_discovery'])} |",
            f"| Recon verified against manifest | {_cell(_bool(forensics['recon_verified']))} |",
            f"| Citations verified | {_cell(_bool(forensics['citations_verified']))} |",
            f"| Archive lines scanned | {_cell(forensics['archive_lines_scanned'])} |",
            f"| Input tokens | {_cell(forensics['input_tokens'])} |",
            f"| Latency | {_cell(_fmt_ms(forensics['latency_ms']))} |",
            f"| Vulnerable file | {_cell(forensics['vulnerable_file'])} |",
            f"| Vulnerable line | {_cell(forensics['vulnerable_line'])} |",
            "",
            f"> {forensics['summary']}",
            "",
        ]
        if forensics["citations"]:
            lines += ["| Log file | Line | Excerpt |", "|---|---|---|"]
            for citation in forensics["citations"]:
                lines.append(
                    f"| {_cell(citation['log_file'])} | {citation['line']} | {_cell(citation['excerpt'])} |"
                )
            lines.append("")
        if forensics["attack_chain"]:
            lines += ["| Timestamp | Source IP | Endpoint | Description |", "|---|---|---|---|"]
            for step in forensics["attack_chain"]:
                lines.append(
                    "| {ts} | {ip} | {ep} | {desc} |".format(
                        ts=_cell(step["timestamp"]),
                        ip=_cell(step["source_ip"]),
                        ep=_cell(step["endpoint"]),
                        desc=_cell(step["description"]),
                    )
                )
            lines.append("")
    else:
        lines += ["_Forensics was not run for this incident._", ""]

    lines += ["## Self-healing patch", ""]
    if patch:
        before = patch["before_status"]
        after = patch["after_status"]
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Applied | {_cell(_bool(patch['applied']))} |",
            f"| Verified | {_cell(_bool(patch['verified']))} |",
            f"| HTTP before → after | {_cell(before)} → {_cell(after)} |",
            f"| Rule | {_cell(patch['rule_id'])} |",
            f"| Fingerprint | `{_cell(patch['rule_fingerprint'])}` |",
            f"| Rolled back | {_cell(_bool(patch['rolled_back']))} |",
            f"| Target file | {_cell(patch['target_file'])} |",
            f"| Model | {_cell(patch['model'])} |",
            f"| Latency | {_cell(_fmt_ms(patch['latency_ms']))} |",
            "",
            f"> {patch['verification_note'] or 'n/a'}",
            "",
        ]
    else:
        lines += ["_No patch was applied to this incident._", ""]

    lines += ["## Integrity", ""]
    integrity = casefile.get("integrity")
    if integrity:
        valid = integrity.get("chain_valid")
        if valid is True:
            verdict = "verified"
        elif valid is False:
            verdict = "BROKEN"
        else:
            verdict = "not recorded (no ledger entry)"
        lines += [
            "| Field | Value |",
            "|---|---|",
            f"| Verdict | `{_cell(verdict)}` |",
            f"| Content SHA-256 | `{_cell(integrity.get('actual_sha256'))}` |",
            f"| Recorded SHA-256 | `{_cell(integrity.get('expected_sha256'))}` |",
            f"| Ledger rows | {_cell(integrity.get('records'))} |",
            f"| Broken at ledger line | {_cell(integrity.get('broken_at_line'))} |",
            f"| Note | {_cell(integrity.get('broken_reason') or 'n/a')} |",
            "",
        ]
    else:
        lines += ["_No integrity ledger check was performed for this export._", ""]

    lines += [
        "---",
        "",
        "Generated by Meta-Guardian. Every value above is derived from the stored",
        "incident record; nothing is summarised by a model at export time.",
        "",
    ]
    return "\n".join(lines)


def casefile_filename(incident: Incident, fmt: str) -> str:
    suffix = "md" if fmt == "markdown" else "json"
    return f"meta-guardian-casefile-{incident.id}.{suffix}"


__all__ = [
    "SCHEMA_VERSION",
    "LEDGER_FILENAME",
    "IncidentLedger",
    "build_casefile",
    "canonical_incident_json",
    "casefile_filename",
    "incident_content_hash",
    "incident_timings",
    "render_markdown",
]
