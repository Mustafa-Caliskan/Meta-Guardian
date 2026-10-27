# Meta-Guardian

**Autonomous cyber-physical security, live quarantine and self-healing SOC agent.**

Meta-Guardian fuses live camera vision with real-time OS/USB and network telemetry at the edge, neutralizes active threats via an open-weight MCP agent, and autonomously hot-patches vulnerable services in the cloud.

Built for the **Meta Global AI Developer Hackathon 2026** (Indie Track) by Mustafa Çalışkan.

---

## Why it is different

Most security demos stop at a dashboard. Meta-Guardian closes the loop:

1. **Real triggers** — a physical USB stick inserted into the machine (`psutil`) or a real request against a local FastAPI target service.
2. **Real physical verification** — the webcam frame at incident time is analyzed to confirm whether an authorized operator is present (ghost-attack detection) or someone plugged in removable media.
3. **Real containment** — MCP tools quarantine the payload file, block the attacker IP and revoke the session token.
4. **Real self-healing** — the vulnerable endpoint is hot-patched, then the *same* attack is replayed live: `HTTP 200 (data leaked)` becomes `HTTP 403 (blocked)`.

No fake door locks, no simulated server rooms.

## Architecture

```
Webcam / USB / target API
          │
          ▼
  Edge watcher + correlator        (backend/edge)
          │
          ▼
  Vision evidence (SAM 3.1)        (backend/vision)
          │
          ▼
  OODA decision + MCP actions      (Muse Glimmer)
          │
          ▼
  1M-context forensics             (Muse Spark 1.3 / Spark Open)
          │
          ▼
  Live auto-patch + replay test    (Muse Spark 1.3 plans the rule)
```

## Repository layout

```
backend/
  main.py            FastAPI control server + WebSocket SOC stream (port 8000)
  target_service.py  Protected Aviation Ops microservice (port 8001)
  config.py          Environment-driven settings and runtime modes
  models.py          Pydantic schemas shared by every layer
  llm/               Provider abstraction: mock, replay, live, record
  vision/            Webcam capture, ROI detection, SAM bridge
  edge/              USB/network watcher, policy engine, OODA agent, MCP server
  cloud/             Sanitizer, forensics, hot-patcher
frontend/            Dark SOC cockpit (vanilla JS, no Streamlit)
data/                Scenario frames, 30-day SIEM archive, replay fixtures
scripts/             Data generation, attack trigger, benchmarks
tests/               Pytest unit and integration tests
```

## Quickstart

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/generate_data.py
python scripts/generate_scenario_frames.py
python scripts/smoke_test_providers.py
python -m pytest
```

The default `.env` runs in `LLM_MODE=mock`, so the whole system works with **no API keys and no internet**.

Run the two services in separate terminals, then open the cockpit:

```powershell
python -m backend.target_service     # protected Aviation Ops API, port 8001
python -m backend.main               # control center + SOC cockpit, port 8000
# then browse http://127.0.0.1:8000
```

The cockpit's scenario injector runs the real pipeline (edge event -> vision ->
OODA -> policy -> MCP containment) and streams everything over `/ws`.

Before a live demo, check real provider model IDs:

```powershell
python scripts/smoke_test_providers.py --probe
```

### Runtime modes

| Mode | Behaviour |
|---|---|
| `mock` | Deterministic canned model responses. Fully offline development and UI work. |
| `replay` | Replays recorded fixtures from `data/fixtures/`. Demo recording insurance. |
| `live` | Calls Meta / Baseten / Fireworks OpenAI-compatible endpoints. |
| `record` | Calls live endpoints and stores the replies as replayable fixtures. |

### Model routing (verified against `dev.meta.ai/docs`)

| Layer | Provider | Model | Notes |
|---|---|---|---|
| Edge OODA | self-hosted / Fireworks / Baseten | `muse-glimmer` | Open-weight. Exact served id depends on your endpoint; verify with the smoke test. |
| Forensics (1M ctx) | Meta Model API | `muse-spark-1.3` | Hosted; set `MODEL_API_KEY` ( `META_API_KEY` also accepted). |
| Patch planning | Meta Model API | `muse-spark-1.3` | Deterministic templates only. |
| Physical verification | Meta Model API | `sam-3.1` | One frame per event, not 30 FPS. |
| Open-weight bonus | Baseten | `meta-models/muse-spark-open-1026` | Hackathon participant-guide override of `meta-models/muse-spark-open`. |

`muse-spark-open-1m` is **not** a Model API model id; the 1M context lives on
`muse-spark-1.3`. **Muse Code is a terminal/CI coding agent, not an API model** —
use `muse-spark-1.3` to generate patch plans.

## Detection pipeline (Days 3-6)

```
event -> capture_frame() -> detect_motion() -> SAMBridge.segment()
      -> OODAAgent.observe/orient -> decide (LLM, JSON validated)
      -> PolicyEngine.evaluate (tickets + confidence + rate limit)
      -> MCPServer.call_tool (real containment) -> Incident
```

- **Vision** (`backend/vision/`): one frame per event, OpenCV webcam with a
  recorded-scenario fallback, frame-diff ROI, and a `sam-3.1` Responses-API
  client. Without `MODEL_API_KEY` it uses the diff mask offline.
- **MCP** (`backend/edge/mcp_server.py`): `quarantine_usb_file`,
  `block_ip_on_gateway`, `revoke_session_token`, `kill_process` - all real side
  effects, plus a JSON-RPC `tools/list` / `tools/call` surface.
- **Policy** (`backend/edge/policy_engine.py`): change-ticket authorization,
  confidence bands (`>= 0.85` auto, `0.50-0.85` approval, `< 0.50` monitor) and
  a sliding-window rate limiter. The LLM can propose, never self-authorize.
- **Correlator** (`backend/edge/correlator.py`): the bridge that was missing.
  Watchers publish individual events; the correlator bundles them (USB + network
  within 30 s, admin command, or a delayed USB-only bundle) and wakes the agent.
  A short per-signature cooldown stops event storms from spawning duplicates.
- **Presence** (`backend/vision/operator.py`): `operator_present` is computed
  from pixels ? motion against a calibrated baseline ? then the ROI is sent to
  SAM 3.1. It is a motion heuristic, not face recognition; if the frame differs
  from the baseline by more than 45% it reports *presence unknown* instead of
  guessing (this prevents false Ghost Attack verdicts).
- **OODA** (`backend/edge/ooda_agent.py`): validates the LLM JSON, replaces
  hallucinated IPs/sessions with evidence, executes only policy-approved actions
  and returns a fully populated `Incident` (scenarios A/B/C).
- **Forensics** (`backend/cloud/forensics.py`): sanitized bundle + prioritized
  archive excerpts go to the 1M-context model. **Every citation is verified
  against the real file and line**; invented lines are dropped and the
  deterministic manifest report is used instead. `earliest_discovery` is
  cross-checked against the archive manifest.
- **Patcher** (`backend/cloud/patcher.py`): the model never writes executable
  code. It selects an allowlisted template, the rule is hot-loaded, the *same*
  attack is replayed and must return 403/401. If it does not, the patch is
  rolled back automatically. A stable rule fingerprint is recorded.

## Real detection loop (not the demo button)

The cockpit has a scenario injector, and it is labelled as such: it injects
synthetic *events* but still runs real vision, policy and containment. Real
detection does not depend on it.

```powershell
# terminal 1
python -m backend.target_service
# terminal 2 (watchers on by default)
python -m backend.main
# terminal 3: real HTTP attack against :8001, waits for the incident, patches
python scripts/trigger_attack.py --reset --exfil --watch --patch
```

`trigger_attack.py` never calls `/api/simulate`. It sends real requests; the
NetWatcher tails the audit log; the correlator builds the incident; the agent
decides; MCP blocks the IP and revokes the session; the patcher proves
`HTTP 200 -> HTTP 403`.

To keep the attacker IP realistic behind a local proxy:

```powershell
$env:TRUST_FORWARDED_FOR="1"          # opt-in, off by default
$env:INTERNAL_API_TOKEN="dev-token"   # protects /internal/* on the target
python scripts/trigger_attack.py --exfil --xff 203.0.113.66 --watch --patch
```

## Recording replay insurance

`LLM_MODE=replay` is only useful with real recordings. This repository ships
two, recorded against Baseten `meta-models/muse-spark-open-1026`:

```powershell
python scripts/record_fixtures.py --provider baseten --model meta-models/muse-spark-open-1026
python scripts/record_fixtures.py --list
```

- `data/fixtures/ooda.json` ? real edge decision (`THREAT_CRITICAL`)
- `data/fixtures/forensics.json` ? real report with line-verified citations

Patch planning is intentionally **not** recorded: it is deterministic and does
not ask a model for code.

## Calibrate operator presence

```powershell
# step away from the desk, then:
python scripts/calibrate_baseline.py
$env:BASELINE_FRAME="data/runtime/baseline.png"
```

The default baseline is the synthetic desk used by recorded scenarios. With a
real webcam, an uncalibrated baseline is correctly reported as *presence
unknown* rather than a confident wrong answer.

## Measured KPIs

```powershell
python scripts/benchmark_latency.py            # mock LLM, real pipeline
python scripts/benchmark_latency.py --patch    # adds patch + 200->403 verification
```

Writes `data/runtime/kpi_report.json` with MTTD, MTTC, patch latency, end-to-end
latency, precision/recall over A/B/C and the assumed bandwidth saving. The script
labels stub timings when the target is down; it never presents them as real.

Last local run (Windows, mock LLM, real target on `:8001`, `--patch`):

| Metric | Value |
|---|---|
| MTTD (edge correlation) | 0.20 ms |
| MTTC (containment, 3 actions incl. HTTP) | 816 ms |
| Patch + replay verification | 1 460 ms |
| End-to-end (trigger -> 403 proven) | 1 758 ms |
| Precision / recall (A, B, C) | 1.00 / 1.00 |
| False positives on Scenario C | 0 |
| Patch verified | `HTTP 200 -> 403` |

These are single-machine numbers from one run, not a benchmark suite. Live LLM
mode adds model latency on top (the recorded OODA call took ~2.8 s).

Scenario C (authorized maintenance) needs a local ticket file:

```powershell
Copy-Item data/change_tickets.example.json data/change_tickets.json
# edit the window so it covers "now", then run the OODA loop
```

`data/change_tickets.json` is git-ignored; only the example is committed.

## Day 4 cockpit

`backend/main.py` is the control center (port 8000). `frontend/` is a hand-written
dark SOC cockpit: vanilla HTML/CSS/JS, **no Streamlit, no framework, no build
step**.

| Surface | Purpose |
|---|---|
| `GET /` + `/static/*` | SOC cockpit (single page) |
| `GET /api/state` | counters, model badges, latest incident |
| `GET /api/events` | recent edge events |
| `GET /api/incidents` | incident history |
| `GET /api/incidents/{id}/frame`, `/mask` | camera frame + SAM mask evidence |
| `GET /api/gateway` | proxied target gateway state (blocked IPs, revoked sessions, WAF rule) |
| `POST /api/simulate` | run scenario A/B/C through the real pipeline |
| `POST /api/incidents/{id}/approve` | execute pending actions (approval band) |
| `POST /api/incidents/{id}/dismiss` | close an incident without action |
| `WS /ws` | live event + incident + state stream |

The UI shows a live log feed, the vision evidence card, an OODA timeline, gateway
containment state, model badges and approval/dismiss buttons.

Fallback frames are synthetic, not photos: regenerate them with
`python scripts/generate_scenario_frames.py`. On a machine with a webcam the real
frame is captured at incident time instead.

Known Windows fix included: OpenCV's `imwrite`/`imread` cannot handle non-ASCII
paths (e.g. a Turkish user folder), so frames are encoded in memory and written
with `Path.write_bytes`.

## 1M-context evidence

The per-incident forensics path is retrieval-first: prioritized excerpts plus
line-by-line citation verification. That is the *defensible* design, but it does
not by itself prove the 1M-context claim.

A one-off full-archive run does. `scripts/forensics_full_archive.py` sent
**1,026,768 input tokens in a single request** to Baseten
`meta-models/muse-spark-open-1026` (hard limit 1,048,544) and completed in 13.5 s:

- All 7 citations verified against real archive lines.
- `earliest_discovery` matched the archive manifest exactly (`2026-10-23T16:43:00Z`).
- The model quoted text verbatim but miscounted line numbers; each excerpt was
  resolved by a unique verbatim match and the correction is recorded.
- The full file is ~1.068M tokens, so the oldest ~4% of benign traffic was
  trimmed. All attacker activity was inside the slice.

Details: [`docs/FULL_ARCHIVE_RUN.md`](docs/FULL_ARCHIVE_RUN.md).
Replay record: `data/fixtures/forensics_full_archive.json`.

State it on camera as a validation run, not as the per-incident path.

## Docker

```bash
docker compose up --build     # target-api :8001 + soc-cockpit :8000
```

The physical sensor (webcam, `psutil` USB) stays on the host because a container
cannot observe host devices. Everything else runs in the stack. Details and
constraints: [`docs/DOCKER.md`](docs/DOCKER.md).

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, trust boundaries,
  sanitized demo scenarios, and the measured KPI table.

## Status

- [x] Day 1 — repository skeleton, configuration, shared schemas, LLM provider layer (mock / replay / live / record)
- [x] Day 2 — target service (`200 → 403` ready), USB/network watchers, deterministic 30-day SIEM archive with line-verified citations
- [x] Day 3 — vision pipeline, MCP quarantine tools, policy engine, OODA agent (93 tests, live containment verified)
- [x] Day 4 — FastAPI control center, WebSocket stream, dark SOC cockpit, approval flow
- [x] Day 5 — correlator, pixel-based presence detection, sanitizer, citation-verified 1M forensics
- [x] Day 6 — real trigger script, live auto-patch with `200 → 403` verification + rollback, KPI benchmark, gateway hardening
- [ ] Day 7 — live runs, feature freeze, video

## Known limitations (stated on purpose)

- Operator presence is a **motion heuristic** against a calibrated baseline. If
  the camera moved or lighting changed, the system says *presence unknown*
  instead of guessing.
- The attacker, victim and defender run on one host. `X-Forwarded-For` is an
  opt-in demo affordance, not a real proxy.
- The gateway blocklist and revoked sessions are in-memory; a target restart
  clears them. Incidents *are* persisted to `data/runtime/incidents/`.
- The bandwidth-saving number is arithmetic (1 frame/event vs 30 FPS for 30 s),
  not a network measurement.
- Cloud output is verified, not trusted: citations must match real lines and the
  patch must prove a 403, otherwise the system falls back or rolls back.
- Removable-media detection uses filesystem and mount options (`removable`,
  `vfat`, `exfat`). It deliberately ignores fixed, network and image mounts, which
  means a USB disk formatted NTFS without the `removable` flag can be missed.
- Operator presence requires a calibrated baseline. If the camera moves, the
  system reports *presence unknown* and never claims a Ghost Attack; a model that
  still claims one is downgraded to human approval by the policy gate.
- The OODA pipeline is serialized by one lock, so a slow live model call queues
  the next correlated bundle.

## License

MIT
