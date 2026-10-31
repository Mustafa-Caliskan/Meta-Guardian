# Demo runbook

Ten minutes before recording. Follow in order; each step has a verification
line so you never discover a problem on camera.

---

## 0. Feature freeze checklist (one minute)

```powershell
python -m pytest
```

Expected: all tests pass. If not, stop and fix before recording.

```powershell
git status --short
```

Expected: clean (or only intentional changes).

---

## 1. Configure the environment

Create `.env` from `.env.example` and set:

```ini
LLM_MODE=live                 # mock only for a dry run, never for the final take
MODEL_API_KEY=<Meta key>      # only needed for SAM 3.1 live calls
BASETEN_API_KEY=<Baseten key> # Spark Open: meta-models/muse-spark-open-1026

TRUST_FORWARDED_FOR=1         # lets the attacker IP look realistic behind loopback
INTERNAL_API_TOKEN=dev-token  # protects /internal/* on the target
MG_COCKPIT_TOKEN=dev-cockpit  # protects the cockpit API; the browser will prompt
MG_COCKPIT_OPERATOR=mustafa   # recorded as the approver on human decisions

BASELINE_FRAME=data/runtime/baseline.png
OPERATOR_MOTION_THRESHOLD=0.004
```

Why `TRUST_FORWARDED_FOR=1` matters: without it the TCP peer is `127.0.0.1`,
loopback blocking is refused by design, and the incident stays `open` with
`block_ip ... FAIL`. That is correct behaviour but looks like a bug on video.

Why `INTERNAL_API_TOKEN` matters: it protects the target's `/internal/*` routes.

Why `MG_COCKPIT_TOKEN` matters: without it the cockpit API ? including
`POST /api/attack` ? is open to anything that can reach port 8000. With it, open
`http://127.0.0.1:8000/?token=dev-cockpit` once; the token is stored locally and
stripped from the URL. `scripts/trigger_attack.py` reads the same variable, so no
script change is needed.

---

## 2. Calibrate the empty-seat baseline (do this first, once)

1. Sit at the desk, frame the camera how it will be during the demo, then
   **stand up and leave the frame**.
2. Run:

```powershell
python scripts/calibrate_baseline.py --frames 10
```

3. Verify:

```powershell
python -c "from backend.vision import PresenceDetector; from backend.config import get_settings; d=PresenceDetector(baseline_path=get_settings().baseline_frame_path); print(d.detect(d.baseline).to_summary())"
```

Expected: `no operator (...) via baseline_diff` and `reliable=True` implied by a
confidence above 0.5. If it says **scene mismatch**, the camera moved or the
lighting changed: recalibrate.

**Do not skip this.** With an uncalibrated baseline, Scenario B correctly refuses
to claim a ghost attack and the label becomes `THREAT_CRITICAL` with human
approval required. Honest, but it does not demo the Ghost Attack rule.

---

## 2b. USB stick that enumerates as "fixed"

Some Windows sticks and USB-SSDs report no `removable` flag and a NTFS
filesystem, so the removable filter ignores them on purpose. Check the pull-in
first:

```powershell
python -c "from backend.edge.usb_net_watcher import default_partition_provider as p; [print(x.device, x.fstype, x.opts, x.is_removable) for x in p()]"
```

If your stick shows `is_removable=False`, either reformat it as FAT32/exFAT
(preferred, and the event will then show `is_removable: true`), or for the demo
only:

```powershell
$env:MG_USB_ACCEPT_ALL="1"
```

That switch marks every new mount as removable and stamps
`accept_all_mounts: true` into the event, so it is visible on camera. Never
leave it on.

## 3. Start the two services (two terminals)

```powershell
# terminal 1
python -m backend.target_service
# expected: Uvicorn running on http://127.0.0.1:8001

# terminal 2
python -m backend.main
# expected: Uvicorn running on http://127.0.0.1:8000
```

Verify:

```powershell
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8000/api/health
python scripts/smoke_test_providers.py
```

Open `http://127.0.0.1:8000` in the browser. The `mode: live` badge and the model
badges must be visible. The connection badge must be green (`live`).

---

## 4. Sanity check the real loop (30 seconds, not recorded)

```powershell
python scripts/trigger_attack.py --reset --exfil --xff 203.0.113.66 --watch
```

Expected in the cockpit: one Scenario A incident, `THREAT_CRITICAL`,
`policy auto`, three actions `OK`, status `contained`. The vision line must say
`reliable` presence (present) and the motion ratio must be plausible.

If `block_ip ... FAIL` appears: `TRUST_FORWARDED_FOR` is not set, or the services
were started before the variable was exported. Restart both.

Then reset for the take:

```powershell
python scripts/trigger_attack.py --reset
```

---

## 5. The take

### Shot 1 — Cockpit tour (20 s)
Mode badge, model badges, empty log feed, gateway panel: `not applied`, no
blocked IPs.

### Shot 2 — Real attack, real containment (60 s)
Terminal 3, on camera:

```powershell
python scripts/trigger_attack.py --reset --exfil --xff 203.0.113.66 --watch --patch
```

Say while it runs: this is a real HTTP request against the protected service, not
a button. The log line appears, the incident opens, the policy gate runs, MCP
blocks the IP, forensics cites the archive, and the patch is applied and replayed.

Expected ending:

```
patch : MG-WAF-XXXXXX fingerprint=... HTTP 200 -> 403 verified=True
[RESULT] PATCH VERIFIED: HTTP 200 -> HTTP 403
```

### Shot 3 — Ghost attack (40 s)
Sit out of frame (or stay behind the camera), then:

```powershell
python scripts/trigger_attack.py --admin --xff 203.0.113.66 --watch
```

Expected: `Scenario B`, `GHOST_ATTACK`, `policy auto`, session revoked.
If the baseline is not calibrated this becomes `THREAT_CRITICAL / approval` — cut
this shot rather than explain a wrong label on camera.

### Shot 4 — Authorized maintenance, zero false alarm (25 s)
For the recorded path use the cockpit: `POST /api/simulate` scenario **C**.
Label it honestly as the demo injector. Expected `BENIGN_AUTHORIZED`, `monitor`,
`dismissed`, zero actions.

### Shot 5 — Evidence and 1M context (30 s)
Show the frame + SAM mask card, then the OODA timeline, then:

```powershell
python scripts/forensics_full_archive.py --verify-only
```

Say: "one request, 1,026,768 input tokens, seven citations verified against real
lines, earliest reconnaissance matched the manifest exactly." Show
`docs/FULL_ARCHIVE_RUN.md`.

### Shot 6 — Close (15 s)
Architecture line + "the model may propose; the policy gate and the replay proof
decide."

---

## 5b. Optional shots added after day 7

**Live metrics strip (10 s).** Point at the strip above the grid: MTTD, MTTR,
self-heal, and the `1,026,768 tok` badge. Say the numbers are computed from the
incidents on screen, not typed in. Hover the badge and mention
`docs/FULL_ARCHIVE_RUN.md`.

**Camera tamper (10 s, optional).** Cover the lens with your hand while a
privileged command runs (`python scripts/trigger_attack.py --admin --watch`).
Expect an amber `CAMERA TAMPERED` badge, the banner `CAMERA TAMPERED · FAIL-CLOSED`,
policy mode `approval`, and zero executed actions. Say: "blinding the sensor does
not hide the attack, it just moves the decision to a human."

**Credential misuse / console collision (15 s).** The attacker uses the hijacked
admin session `session-ext-admin` — the same operator identity, but established
from an external address — while the camera shows someone at the desk:

```powershell
python scripts/trigger_attack.py --admin --watch
```

Expect `CREDENTIAL_MISUSE`, policy mode `approval` (never automatic), an
`origin 203.0.113.66` pill and the banner `CREDENTIAL MISUSE … approval required`.
Say: "the audit log looks exactly like the real admin's own work; only the camera
can tell that the person holding the token is not the person sitting here."

**One `.env` for every scenario.** `MG_MANAGEMENT_NETWORKS=10.0.0.0/8` is safe to
leave set: the misuse demo uses the externally-established session, so it stays
"remote". The office-LAN session (`session-7f3a9c`, origin `10.0.0.31`) counts as
management traffic, which is what the legitimate-remote-IT rule (row 1) needs.

**Not true any more:** scenario C does **not** depend on `MG_MANAGEMENT_NETWORKS`.
It is suppressed by ticket owner + admin role + a present operator, so it returns
`BENIGN_AUTHORIZED` with the variable empty as well.

**DEGRADED gösterimi (opsiyonel, 20 s).** Rozeti göstermek için: `.env` içinde
`LLM_MODE=live` + bilerek geçersiz bir `MODEL_API_KEY` ile başlat, exfil tetikle
→ `DEGRADED · fallback` rozeti + `APPROVAL` görünür (model ölse bile tespit ve
insan onayı çalışır). Mock modda model asla düşmez; rozetin normal demoda
görünmemesi doğru davranıştır.

**SAM provenance (10 s).** In the evidence card hover the mask. The method line
must read `baseline_diff->sam-vit_b@modal` (or `->sam-3.1`). If it reads
`sam-offline`, the Modal endpoint is not configured and the mask is geometry ?
do not call it a model output.

**Benchmark (15 s).** `python scripts/benchmark_baseline.py --patch` (stop the
compose cockpit first, see docs/DOCKER.md). Show the naive engine missing the
ghost attack and false-alarming on the maintenance window.

## 6. What not to say

- Do not say `/api/simulate` is real detection. It is a labelled injector.
- Do not say the model localized the vulnerable line; the live forensics output
  returned `vulnerable_file: null` and the patcher supplies the target
  deterministically.
- Do not say presence detection is biometric. It is motion vs a calibrated
  baseline.
- Do not present the bandwidth figure as measured. It is arithmetic
  (1 frame/event vs 30 FPS for 30 s).
- Do not claim full 1M context in the per-incident path. It is a one-off
  validation run; per incident the system sends prioritized excerpts.

---

## 7. If something breaks on camera

| Symptom | Cause | Fix |
|---|---|---|
| `block_ip ... FAIL` | loopback peer, XFF off | set `TRUST_FORWARDED_FOR=1`, restart both |
| `presence unknown` / scene mismatch | baseline stale | recalibrate, restart `backend.main` |
| `GHOST_ATTACK` never appears | uncalibrated baseline or no admin event | recalibrate; use `--admin` |
| forensics says `manifest-fallback` | live model down | that is the designed fallback; say so |
| patch `verified=False` | target rule rejected or attack changed | `--reset`, rerun; check `--patch` |
| no incident at all | watchers off or wrong log path | run `python -m backend.main` (watchers default on) |

Replay insurance (network down):

```powershell
$env:LLM_MODE="replay"
```

`data/fixtures/ooda_A.json`, `ooda_B.json`, `ooda_C.json` and `forensics.json`
were recorded from Baseten `meta-models/muse-spark-open-1026` with the current
prompt. Re-record after any prompt change with
`python scripts/record_fixtures.py --provider baseten`.

---

## 8. Known operational notes

- The OODA pipeline runs under a single lock, so a slow live LLM call (up to the
  request timeout) queues the next correlated bundle. Fine for a solo demo; do
  not fire two attacks within a few seconds of each other on camera.
- Incidents persist to `data/runtime/incidents/`. Delete that folder for a clean
  take if you want an empty incident list at the start.
- Gateway blocklist and revoked sessions are in-memory; restarting
  `backend.target_service` clears them.
