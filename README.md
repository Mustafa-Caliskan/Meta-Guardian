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

## Day 3 pipeline

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
- **OODA** (`backend/edge/ooda_agent.py`): validates the LLM JSON, replaces
  hallucinated IPs/sessions with evidence, executes only policy-approved actions
  and returns a fully populated `Incident` (scenarios A/B/C).

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

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, trust boundaries,
  sanitized demo scenarios, and the measured KPI table.

## Status

- [x] Day 1 — repository skeleton, configuration, shared schemas, LLM provider layer (mock / replay / live / record)
- [x] Day 2 — target service (`200 → 403` ready), USB/network watchers, deterministic 30-day SIEM archive with line-verified citations
- [x] Day 3 — vision pipeline, MCP quarantine tools, policy engine, OODA agent (93 tests, live containment verified)
- [x] Day 4 — FastAPI control center, WebSocket stream, dark SOC cockpit, approval flow (110 tests, live MVP verified)
- [ ] Day 5 — sanitizer + 1M-context forensics
- [ ] Day 6 — live hot-patch and `200 → 403` verification
- [ ] Day 7 — live runs, benchmarks, feature freeze

## License

MIT
