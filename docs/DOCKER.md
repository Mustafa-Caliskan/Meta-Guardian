# Running Meta-Guardian with Docker

Two containers, one build. The physical edge sensor stays on the host.

```
host (Windows/macOS/Linux)
  webcam + psutil USB + baseline calibration   <- cannot live in a container
  scripts/trigger_attack.py (real HTTP attacker)

docker compose
  target-api     protected Aviation Ops API   :8001
  soc-cockpit    detection, policy, MCP, forensics, patching, UI   :8000
```

Why the sensor is not containerised: a container cannot see the host's camera or
USB devices. Pretending otherwise is the kind of thing a reviewer notices. The
architecture is honest: sensors on the edge, control plane deployable.

## Quickstart

```bash
cp .env.example .env      # optional: set MODEL_API_KEY / BASETEN_API_KEY
docker compose up --build
# open http://127.0.0.1:8000
```

Verify:

```bash
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8000/api/health
docker compose ps
```

Both services should report `healthy`.

## Run the real attack against the containers

```bash
# from the host, same repo
python scripts/trigger_attack.py --reset --exfil --xff 203.0.113.66 --watch --patch
```

The target writes its audit log to `./data/runtime/target_requests.jsonl`, which
is bind-mounted into both containers, so the control plane tails the same file it
would tail on the host. `TARGET_HOST=target-api` makes the control plane reach the
target by container DNS instead of loopback.

Expected: Scenario A incident, `contained`, then `patched` with
`HTTP 200 -> 403 verified=True`.

## Run scenarios and forensics from the cockpit/API

```bash
curl -X POST http://127.0.0.1:8000/api/simulate -H 'content-type: application/json' -d '{"scenario":"A"}'
curl -X POST http://127.0.0.1:8000/api/incidents/<id>/forensics
curl -X POST http://127.0.0.1:8000/api/incidents/<id>/patch
```

## Configuration

| Variable | Where | Meaning |
|---|---|---|
| `TARGET_HOST` | soc-cockpit | `target-api` in compose, empty means `HOST` |
| `ENABLE_WATCHERS` | soc-cockpit | start USB/network watchers (default `1`) |
| `INTERNAL_API_TOKEN` | both | shared secret for `/internal/*`; compose defaults to `dev-token` |
| `TRUST_FORWARDED_FOR` | target-api | compose defaults to `1` so `--xff` gives a realistic attacker IP |
| `MG_TARGET_LOG` | target-api | audit log path, shared via the `./data` volume |
| `LLM_MODE` | soc-cockpit | `mock` / `replay` / `live` / `record` |
| `MODEL_API_KEY` | soc-cockpit | Meta Model API key for SAM 3.1 |
| `BASETEN_API_KEY` | soc-cockpit | Spark Open (`meta-models/muse-spark-open-1026`) |

## Segmentation inside the stack

Set `MODAL_SAM_URL` and `MODAL_SAM_TOKEN` in `.env`; compose passes them to
`soc-cockpit`. The container has no camera, so frames come from the recorded
scenario images, but the mask is produced by the real Modal model. Verify:

```bash
docker compose exec soc-cockpit python scripts/test_modal_sam.py --bridge
```

## Running the benchmark against this stack

The benchmark needs exclusive control of the target. The `soc-cockpit` container
also runs watchers, so two control planes would race for the same log file:

```bash
docker compose stop soc-cockpit
python scripts/benchmark_baseline.py --patch
docker compose start soc-cockpit
```

## Known constraints inside containers

- **No webcam.** `BASELINE_FRAME` points at the synthetic baseline, so presence is
  reported as *unknown* and any ghost claim is downgraded to human approval by the
  policy gate. That is the designed behaviour, not a bug. For a calibrated demo run
  the control plane on the host (see `docs/DEMO_RUNBOOK.md`).
- **No USB visibility.** USB detection must run on the host.
- **Loopback blocking is refused.** Never try `--xff 127.0.0.1`; it is rejected by
  design so the stack cannot lock itself out.
- State: incidents persist in `./data/runtime/incidents/`, quarantined files land
  in `./quarantine/`. Both are bind mounts, so `docker compose down` keeps them.

## Linux permission note

The image runs as uid `10001`. Bind mounts keep host ownership, so on Linux:

```bash
sudo chown -R 10001:10001 data quarantine
```

or, for local-only use, uncomment `user: "0:0"` in `docker-compose.yml`.
Windows and Docker Desktop do not need this.

## What is verified so far

- `docker compose config -q` passes (manifest is valid).
- The image build is exercised in CI (`.github/workflows/ci.yml`).
- Local build on this machine needs Docker Desktop running; it was not available
  at commit time, so a local `docker compose up` has not been recorded yet. Do not
  claim it works until that run is done.

## Rebuilding

```bash
docker compose build --no-cache
docker compose up
```
