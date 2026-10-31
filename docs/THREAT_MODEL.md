# Meta-Guardian — Threat Model, Demo Scenarios & KPIs

This document is the source of truth for **what is real**, **what is measured**
and **what is out of scope**. It exists because a security demo is only credible
if its claims survive a hostile reviewer.

---

## 1. Assets and trust boundaries

| Asset | Where | Why it matters |
|---|---|---|
| Aviation Ops API (`backend/target_service.py`, port 8001) | Local host | Simulated operational microservice. Holds flight/ops records. |
| Edge sensor host (webcam + `psutil` + log tail) | Local host | Observes physical and OS-level events. |
| SOC decision agent (Muse Glimmer, self-hosted) | Edge / local | Must decide fast without shipping camera frames to the cloud. |
| Forensics + patch planner (Muse Spark 1.3, 1M ctx) | Cloud API | Sees only sanitized evidence + 30-day SIEM archive. |
| 30-day SIEM archive (`data/history_logs/`) | Local file | Synthetic but realistic; every citation is line-verifiable. |

Trust boundaries:

```
[ physical world ] --camera--> [ edge host ] --sanitized evidence--> [ cloud LLM ]
                                     |                                     |
                                     +--MCP actions--> [ target service ] <+
```

- Camera frames **never** leave the host. Only a text description, a boolean
  `operator_present`, a confidence value and a cropped ROI hash are sent.
- API keys stay in `.env`; `.env` is git-ignored; smoke tests never print keys.
- The LLM may only select a **pre-approved patch template and bounded
  parameters**. It never emits executable code that is run directly.

## 2. Adversaries and threats

| # | Adversary | Technique | Detection signal | Containment |
|---|---|---|---|---|
| T1 | Local insider / visitor | Inserts removable media with an unsigned PowerShell payload | `psutil` partition-added event + file scan (`payload.ps1`) + camera ROI | Quarantine file, record SHA-256 |
| T2 | Remote attacker | Unauthenticated exfiltration against `/api/v1/ops/data` | Request log tail: endpoint + missing session + exfil markers | Block source IP, revoke session |
| T3 | Remote attacker | Reconnaissance days before the attack | 1M-context scan of 30-day archive, timestamp validation | Foresnsics report with citations |
| T4b | Remote attacker with a stolen admin token | Hijacked admin session issued from a remote origin while the legitimate operator sits at the console | Camera: `operator_present == true` **and** session origin outside loopback/management networks during a privileged call | Classify `CREDENTIAL_MISUSE`, never auto-contain, require human approval |
| T4 | Remote attacker | "Ghost" admin command while the seat is empty | Camera: `operator_present == false` during privileged call | Revoke session, classify `GHOST_ATTACK` |
| T5 | Malicious or careless engineer | Legitimate maintenance during an approved window | Change ticket covers timestamp **and** operator present | Classify `BENIGN_AUTHORIZED`, no action |
| T6 | Reviewer | LLM hallucinates a log line or a patch | Citation verifier + deterministic patch template + rollback | Report rejected, no change applied |

### Explicit non-claims

- **No USB autorun.** Modern Windows ships with Autorun for removable media
  disabled. Scenario A does **not** claim the script executed by itself. The
  claim is: *suspicious executable content on removable media was detected,
  hashed and quarantined before execution.*
- **No kernel driver / no EDR driver.** USB detection is user-space `psutil`.
- **No real aviation data.** All records are synthetic.
- **No 7/24 video streaming.** That is the point: one frame per event.

## 3. Demo scenarios (sanitized)

### Scenario A — Rogue removable media + API exfiltration
1. An unsigned `payload.ps1` is placed on a USB stick and the stick is inserted.
   The script does **not** run automatically; it is at rest.
2. `psutil` emits a partition event; the edge watcher scans the new volume,
   finds the script, computes its SHA-256 and raises a `HIGH` event.
3. At the same moment a request without a session token hits
   `GET /api/v1/ops/data?aircraft=ALL` and receives `HTTP 200` (the leak).
4. The webcam frame at incident time is analyzed; an operator is present but no
   change ticket covers the window → `THREAT_CRITICAL`.
5. MCP actions: quarantine `payload.ps1`, block `203.0.113.66`, revoke
   `session-7f3a9c`.
6. Muse Spark 1.3 finds the 3-days-earlier reconnaissance line in the 30-day
   archive, cites file + line, and proposes a template-based rule.
7. The rule is hot-loaded into the target service; the **same** request is
   replayed: `HTTP 200` → `HTTP 403`. Patch fingerprint and both statuses are
   reported.

### Scenario B — Ghost attack (remote shell, empty seat)
1. No operator is visible in the camera frame.
2. A privileged command is executed against `/api/v1/admin/command`.
3. Classification `GHOST_ATTACK`; session is revoked and the IP blocked.
4. This is the case a passive dashboard cannot catch.

### Scenario C — Authorized maintenance (zero false alarms)
1. An engineer is present **and** `change_tickets.json` covers the timestamp.
2. Classification `BENIGN_AUTHORIZED`; **no** quarantine, **no** block.
3. Proof that the policy engine, not the LLM alone, gates destructive actions.

## 4. KPI table (measured, not claimed)

`scripts/benchmark_latency.py` emits a `KPIReport` for each scenario. Targets are
checked in CI-style tests where deterministic; live targets are recorded.

Measured values are written to `data/runtime/kpi_report.json`. The script labels
stub timings when the target is down and labels the bandwidth figure as an
arithmetic assumption. Nothing in this table is published as measured unless the
benchmark produced it.

| KPI | Definition | Target | How measured |
|---|---|---|---|
| **MTTD (edge)** | trigger timestamp → correlated `SecurityEvent` | < 2 s | event timestamps |
| **MTTC (containment)** | decision start → last MCP action success | < 1 s | `MCPActionResult.executed_at` |
| **Patch + verify** | forensics start → replayed `403` | < 90 s live, < 5 s mock | `PatchResult` timestamps |
| **End-to-end** | trigger → verified patch | < 120 s live, < 10 s mock | incident timestamps |
| **Detection precision** | true positives / all raised incidents | ≥ 0.90 | 3-scenario suite |
| **Detection recall** | A and B detected / 2 | 1.00 | 3-scenario suite |
| **False positive rate** | C misclassified / 1 | 0.00 | Scenario C |
| **Cloud calls / incident** | forensics + patch plan (+1 SAM) | ≤ 3 | provider call counter |
| **Video tokens saved** | 1 frame per event vs 30 FPS streaming | > 99.9 % | arithmetic, documented |
| **Citation validity** | cited line exists **and** excerpt matches | 100 % | `backend/cloud/citations.py` test |
| **Patch safety** | bad/unknown template rejected, rollback works | 100 % | unit tests |
| **Determinism (replay)** | identical classification across 3 replays | 3/3 | replay test |

### Why these KPIs win Technical Depth
- They are **falsifiable**: a reviewer can rerun the tests and diff the numbers.
- They separate **edge latency** (local, sub-second) from **cloud latency**
  (forensics, seconds), which is the honest architecture story.
- They prove the **negative** case (Scenario C) instead of only the happy path.


## 5. Hardening implemented after review

| Risk | Mitigation | Where |
|---|---|---|
| Correlator missing: sensors never woke the agent | `Correlator` bundles events and schedules the OODA run | `backend/edge/correlator.py` |
| `operator_present` hard-coded by scenario | Pixel motion vs calibrated baseline; SAM on the captured frame; `presence unknown` on scene mismatch | `backend/vision/operator.py`, `backend/main.py` |
| Replaying stale log lines on startup | `NetWatcher(ignore_history=True)` starts at EOF | `backend/edge/usb_net_watcher.py` |
| Blocking loopback kills the control plane | Loopback/unspecified IPs refused by MCP and gateway | `backend/edge/mcp_server.py`, `backend/target_service.py` |
| Control plane unauthenticated | Optional shared secret on all `/internal/*` endpoints | `backend/target_service.py` |
| Forged attacker IP | `X-Forwarded-For` honoured only when `TRUST_FORWARDED_FOR=1`; raw peer always logged | `backend/target_service.py` |
| Unbounded process killing | Optional `KILL_ALLOWLIST`; system PIDs always refused | `backend/edge/mcp_server.py` |
| Hallucinated log citations | Line + excerpt verification; deterministic manifest fallback | `backend/cloud/forensics.py` |
| Unsafe auto-patch | Allowlisted deterministic template, replay proof, automatic rollback | `backend/cloud/patcher.py` |
| Lost SOC history on restart | Incidents persisted as JSON | `backend/main.py` |
| Model claims GHOST_ATTACK without verified presence | Prompt rule + deterministic downgrade to `THREAT_CRITICAL` with human approval | `backend/edge/ooda_agent.py`, `backend/edge/policy_engine.py` |
| Replay returns the scenario-A verdict for B and C | Scenario-scoped fixture keys (`ooda:A/B/C`) with generic fallback | `backend/edge/ooda_agent.py`, `backend/llm/replay.py` |
| Network/image mount treated as a USB insertion | Removable-only filter on filesystem and mount options | `backend/edge/usb_net_watcher.py` |
| Blocklist can lock out the control plane | Loopback, link-local, RFC1918 and ULA addresses are never blockable | `backend/netguard.py` |
| Patcher replay re-triggers the detector | Probes carry `x-mg-probe` **equal to the internal secret**; the header is ignored entirely when no token is configured | `backend/target_service.py`, `backend/cloud/patcher.py` |
| Public detection bypass via a fixed marker | The marker is authenticated with `INTERNAL_API_TOKEN` (constant-time compare); a public value would be a documented evasion | `backend/target_service.py` |
| MTTD understated by the log poll interval | Event timestamps come from the request's own `ts` field, not from the tailer read time | `backend/edge/usb_net_watcher.py` |
| Slow segmentation freezing the cockpit | Segmentation is scheduled after publish, outside the bundle lock | `backend/main.py` |
| Privileged command from a remote origin while the operator is physically present | Reported as `CREDENTIAL_MISUSE`; always queued for human approval, never auto-contained | `backend/edge/policy_engine.py`, `backend/edge/ooda_agent.py` |
| Camera tampering (covered lens) read as "empty seat" | Flat/dark/blown-out frames are reported as `tampered`, never as presence, and a privileged command during tampering fails closed to human approval | `backend/vision/operator.py`, `backend/edge/policy_engine.py` |

## 6. What the demo must not claim

- That `/api/simulate` is real detection. It is a labelled demo injector.
- That presence detection is biometric identification. It is motion analysis.
- That the bandwidth number is measured. It is arithmetic.
- That a vendor agent (Wazuh/CrowdStrike) cannot do parts of this. The novelty is
  the combined physical + network correlation with a deterministic action gate
  and verifiable self-patching, not any single component.

## 7. Control-plane authentication and human accountability

The cockpit (port 8000) can trigger real containment, so it is a privileged
surface. Two modes:

| Mode | When | Behaviour |
|---|---|---|
| `disabled` | `MG_COCKPIT_TOKEN` empty (**local demo default**) | Every `/api/*` except `/api/health` and `/api/config` is open. `/api/config` reports `"cockpit_auth": "disabled"` so the exposure is never hidden. |
| `enabled` | `MG_COCKPIT_TOKEN` set | All `/api/*` require `Authorization: Bearer <token>`; a wrong or missing token gets `401`. `/api/health` and `/api/config` stay open so the browser can discover that a token is needed. The WebSocket requires `?token=`. |

`/api/config` deliberately carries no operator identity and no incident data; it
only advertises whether auth is on.

### Accepted trade-off

The WebSocket token travels as a query parameter, which means it can appear in
reverse-proxy access logs. This is accepted for the demo and documented instead
of hidden. For a production deployment the token should move to the
`Sec-WebSocket-Protocol` header.

### Human decisions are recorded

`approve`, `reject` and `dismiss` store `operator` and a UTC timestamp on the
incident (`decided_by`, `decided_at`) and on the policy outcome
(`approved_by`/`approved_at`, `rejected_by`/`rejected_at`, `rejection_reason`).
The case file renders a **Human decision** section, or states explicitly that no
human was involved when the deterministic gate acted alone.

`reject` executes nothing: it clears the pending actions, marks the incident
`dismissed`, and records the reason.

## 8. Case-file integrity ledger and its limit

Every persisted incident revision appends a row to
`data/runtime/hashchain.jsonl` (`incident_id`, `content_sha256`, `prev_sha256`,
`recorded_at`, `kind`). `GET /api/incidents/{id}/casefile?verify=1` compares the
on-disk record with the last row for that incident and reports `chain_valid`,
plus the ledger line where the chain broke. Approve/reject are legitimate
updates: they append a row instead of rewriting history, so the chain stays
valid.

**Limit, stated plainly:** the ledger is append-only and detects edits that do
not recompute the past (out-of-band file changes, a tampered middle row). It
does **not** protect against an attacker who can rewrite the entire chain: there
is no cryptographic signature and no notarisation. The defensible claim is
**change detection**, not "tamper-proof".
