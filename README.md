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
  OODA decision + MCP actions      (Muse Glimmer 30B)
          │
          ▼
  1M-context forensics             (Muse Spark Open)
          │
          ▼
  Live auto-patch + replay test    (Muse Code)
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
python scripts/smoke_test_providers.py
python -m pytest
```

The default `.env` runs in `LLM_MODE=mock`, so the whole system works with **no API keys and no internet**.

Run the two services in separate terminals:

```powershell
python -m backend.target_service     # protected Aviation Ops API, port 8001
```

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

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, trust boundaries,
  sanitized demo scenarios, and the measured KPI table.

## Status

- [x] Day 1 — repository skeleton, configuration, shared schemas, LLM provider layer (mock / replay / live / record)
- [x] Day 2 — target service (`200 → 403` ready), USB/network watchers, deterministic 30-day SIEM archive with line-verified citations
- [ ] Day 3 — vision pipeline, MCP quarantine tools, policy engine, OODA agent
- [ ] Day 4 — SOC cockpit + WebSocket stream (MVP)
- [ ] Day 5 — sanitizer + 1M-context forensics
- [ ] Day 6 — live hot-patch and `200 → 403` verification
- [ ] Day 7 — live runs, benchmarks, feature freeze

## License

MIT
