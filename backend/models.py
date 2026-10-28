"""Shared Pydantic schemas for Meta-Guardian.

Every layer (edge telemetry, vision, MCP actions, cloud forensics) speaks these
models so the demo pipeline is deterministic and testable end to end.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class EventSource(str, Enum):
    USB = "usb"
    NETWORK = "network"
    PROCESS = "process"
    VISION = "vision"
    MANUAL = "manual"


class EventType(str, Enum):
    USB_INSERTED = "usb_inserted"
    USB_REMOVED = "usb_removed"
    SUSPICIOUS_API_REQUEST = "suspicious_api_request"
    ADMIN_COMMAND = "admin_command"
    UNAUTHORIZED_PROCESS = "unauthorized_process"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    THREAT_CRITICAL = "THREAT_CRITICAL"
    GHOST_ATTACK = "GHOST_ATTACK"
    BENIGN_AUTHORIZED = "BENIGN_AUTHORIZED"
    BENIGN_UNKNOWN = "BENIGN_UNKNOWN"


class ActionType(str, Enum):
    QUARANTINE_USB_FILE = "quarantine_usb_file"
    BLOCK_IP_ON_GATEWAY = "block_ip_on_gateway"
    REVOKE_SESSION_TOKEN = "revoke_session_token"
    KILL_PROCESS = "kill_process"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    PATCHED = "patched"
    DISMISSED = "dismissed"


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: datetime = Field(default_factory=utc_now)
    source: EventSource
    type: EventType
    severity: Severity = Severity.INFO
    summary: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_tz(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class VisionEvidence(BaseModel):
    operator_present: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    roi: list[int] = Field(default_factory=list, description="[x, y, w, h]")
    description: str = ""
    frame_path: str | None = None
    mask_path: str | None = None
    model: str = "sam-3.1"
    method: str = "baseline_diff+sam-3.1"
    motion_ratio: float = 0.0
    frame_source: str = ""
    presence_known: bool = True


class ChangeTicket(BaseModel):
    ticket_id: str
    operator: str
    reason: str
    window_start: datetime
    window_end: datetime
    usb_allowed: bool = False

    @field_validator("window_start", "window_end")
    @classmethod
    def ensure_tz(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def covers(self, moment: datetime) -> bool:
        moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
        return self.window_start <= moment <= self.window_end


class MCPAction(BaseModel):
    action: ActionType
    target: str
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyMode(str, Enum):
    AUTO = "auto"
    APPROVAL = "approval"
    MONITOR = "monitor"


class PolicyOutcome(BaseModel):
    """Deterministic gate between the LLM proposal and real-world actions."""

    classification: Classification
    severity: Severity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mode: PolicyMode
    reason: str = ""
    ticket_id: str | None = None
    operator_present: bool = False
    approved_actions: list[MCPAction] = Field(default_factory=list)
    pending_actions: list[MCPAction] = Field(default_factory=list)
    rate_limited_actions: list[MCPAction] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=utc_now)


class MCPActionResult(BaseModel):
    action: ActionType
    target: str
    success: bool
    detail: str = ""
    executed_at: datetime = Field(default_factory=utc_now)


class OODADecision(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ooda"))
    incident_id: str
    classification: Classification
    severity: Severity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    evidence_summary: str = ""
    actions: list[MCPAction] = Field(default_factory=list)
    model: str = "muse-glimmer-30b"
    latency_ms: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)


class AttackChainStep(BaseModel):
    timestamp: datetime
    source_ip: str | None = None
    endpoint: str | None = None
    description: str


class Citation(BaseModel):
    log_file: str
    line: int = Field(ge=1)
    excerpt: str


class ForensicsReport(BaseModel):
    id: str = Field(default_factory=lambda: new_id("forensics"))
    incident_id: str
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    earliest_discovery: datetime | None = None
    vulnerable_file: str | None = None
    vulnerable_line: int | None = None
    vulnerable_code: str | None = None
    summary: str = ""
    citations: list[Citation] = Field(default_factory=list)
    citations_verified: bool = False
    recon_verified: bool = False
    archive_lines_scanned: int = 0
    model: str = "muse-spark-1.3"
    latency_ms: float = 0.0
    input_tokens: int = 0
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("earliest_discovery")
    @classmethod
    def ensure_tz(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class WAFRule(BaseModel):
    """Deterministic, allowlisted rule that the target service can hot-reload.

    The LLM never writes executable code directly. It may only *select* a
    template, choose parameters from bounded enums and supply a rationale.
    Every rule is hashed so the applied revision is auditable.
    """

    rule_id: str
    blocked_markers: list[str] = Field(default_factory=list)
    require_session: bool = True
    require_operator: bool = False
    allowed_session_prefixes: list[str] = Field(default_factory=list)
    rationale: str = ""

    @property
    def fingerprint(self) -> str:
        import hashlib
        import json

        body = json.dumps(self.model_dump(exclude={"rationale"}), sort_keys=True)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


class PatchPlan(BaseModel):
    """What the cloud layer proposes before anything touches the target."""

    id: str = Field(default_factory=lambda: new_id("plan"))
    incident_id: str
    target_file: str
    template: Literal["require_session", "block_markers", "both"] = "both"
    rule: WAFRule
    llm_rationale: str = ""
    model: str = "muse-spark-1.3"
    latency_ms: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)


class PatchResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("patch"))
    incident_id: str
    target_file: str
    rule_id: str = ""
    rule_fingerprint: str = ""
    rationale: str = ""
    patch_code: str = ""
    applied: bool = False
    rolled_back: bool = False
    before_status: int | None = None
    after_status: int | None = None
    verified: bool = False
    verification_note: str = ""
    model: str = "muse-spark-1.3"
    latency_ms: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)

    def mark_verified(self, before: int, after: int) -> "PatchResult":
        self.before_status = before
        self.after_status = after
        self.verified = after in (401, 403) and before == 200
        self.verification_note = (
            f"HTTP {before} -> HTTP {after}: "
            + ("PATCH VERIFIED" if self.verified else "patch not effective")
        )
        return self


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    status: IncidentStatus = IncidentStatus.OPEN
    scenario: Literal["A", "B", "C", "unknown"] = "unknown"
    events: list[SecurityEvent] = Field(default_factory=list)
    vision: VisionEvidence | None = None
    decision: OODADecision | None = None
    policy: PolicyOutcome | None = None
    action_results: list[MCPActionResult] = Field(default_factory=list)
    forensics: ForensicsReport | None = None
    patch: PatchResult | None = None

    def touch(self) -> "Incident":
        self.updated_at = utc_now()
        return self


class CitationCheck(BaseModel):
    citation: Citation
    exists: bool
    excerpt_matches: bool
    detail: str = ""


class KPIReport(BaseModel):
    """Measured, not claimed. Emitted by benchmark_latency.py."""

    scenario: str = ""
    generated_at: datetime = Field(default_factory=utc_now)
    detection_latency_ms: float = 0.0
    containment_latency_ms: float = 0.0
    patch_latency_ms: float = 0.0
    end_to_end_latency_ms: float = 0.0
    false_positive_rate: float = 0.0
    detection_precision: float = 0.0
    detection_recall: float = 0.0
    tokens_saved_pct: float = 0.0
    cloud_calls_per_incident: int = 0
    notes: str = ""


class MetricsReport(BaseModel):
    """Live metrics computed from real incidents, never hard-coded."""

    incidents: int = 0
    contained: int = 0
    patched: int = 0
    actions_ok: int = 0
    actions_failed: int = 0
    blocked_ips: int = 0
    revoked_sessions: int = 0
    mttd_ms: float | None = None
    mttr_ms: float | None = None
    patch_verify_ms: float | None = None
    events_per_minute: list[int] = Field(default_factory=list)
    blocked_per_minute: list[int] = Field(default_factory=list)
    window_seconds: int = 300
    full_archive_input_tokens: int | None = None
    full_archive_model: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)
