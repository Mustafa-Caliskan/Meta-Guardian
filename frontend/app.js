/* Meta-Guardian SOC cockpit — vanilla JS, no framework, no build step. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const state = {
    config: null,
    snapshot: null,
    incidents: [],
    latest: null,
    events: [],
    gateway: null,
    metrics: null,
    chart: null,
    ws: null,
    wsConnected: false,
    retry: 0,
    startedAt: Date.now(),
    busy: false,
  };

  const MAX_LOG_ROWS = 180;

  /* ------------------------------------------------------------------ utils */

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));

  const pad = (n) => String(n).padStart(2, "0");

  const clock = (iso) => {
    const d = iso ? new Date(iso) : new Date();
    if (Number.isNaN(d.getTime())) return "--:--:--";
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };

  const ago = (iso) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    const secs = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
    return `${Math.round(secs / 3600)}h ago`;
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body.detail) detail = body.detail;
      } catch (_) { /* ignore */ }
      throw new Error(detail);
    }
    return response.json();
  }

  /* --------------------------------------------------------------- rendering */

  function renderBadges() {
    const cfg = state.config;
    const snap = state.snapshot;
    const mode = (snap && snap.mode) || (cfg && cfg.mode) || "—";
    $("modeBadge").textContent = `mode: ${mode}`;

    if (cfg && cfg.models) {
      $("modelOoda").textContent = cfg.models.ooda || "glimmer";
      $("modelSam").textContent = cfg.models.sam || "sam-3.1";
      $("modelSpark").textContent = cfg.models.forensics || "spark";
      $("modelOpen").textContent = cfg.models.spark_open || "spark-open";
    }

    const badge = $("connBadge");
    badge.dataset.state = state.wsConnected ? "on" : "off";
    badge.textContent = state.wsConnected ? "● live" : "● offline";
  }

  function renderStats() {
    const counts = (state.snapshot && state.snapshot.counts) || {};
    $("statEvents").textContent = counts.events ?? state.events.length;
    $("statIncidents").textContent = counts.incidents ?? state.incidents.length;
    $("statContained").textContent = counts.contained ?? 0;
    $("statPending").textContent = counts.pending_approval ?? 0;
    $("incidentCount").textContent = `${state.incidents.length} total`;
  }

  function renderScenarios(list) {
    const host = $("scenarioList");
    host.innerHTML = "";
    list.forEach((item) => {
      const button = document.createElement("button");
      button.className = "scenario";
      button.type = "button";
      button.dataset.scenario = item.id;
      button.innerHTML = `
        <span class="tag">${esc(item.id)}</span>
        <span>
          <span class="s-title">${esc(item.title)}</span>
          <span class="s-detail">${esc(item.detail)}</span>
        </span>
        <span class="s-play">RUN ▸</span>`;
      button.addEventListener("click", () => runScenario(item.id));
      host.appendChild(button);
    });
  }

  /* ------------------------------------------------------------- metrics */

  const fmtMs = (value) => {
    if (value === null || value === undefined) return "?";
    if (value < 1000) return `${Math.round(value)} ms`;
    return `${(value / 1000).toFixed(2)} s`;
  };

  function renderMetrics() {
    const m = state.metrics;
    if (!m) return;

    const mttd = m.mttd_ms;
    const mttr = m.mttr_ms;
    const patch = m.patch_verify_ms;

    $("mttdValue").textContent = fmtMs(mttd);
    $("mttdSub").textContent = m.incidents
      ? `mean over ${m.incidents} incident(s)`
      : "no incidents yet";

    $("mttrValue").textContent = fmtMs(mttr);
    $("mttrSub").textContent = m.actions_ok
      ? `${m.actions_ok} action(s) ok${m.actions_failed ? `, ${m.actions_failed} failed` : ""}`
      : "no containment yet";

    $("patchValue").textContent = fmtMs(patch);
    $("patchSub").textContent = m.patched
      ? `${m.patched} patch(es) verified 200?403`
      : "no patch yet";

    const tokens = m.full_archive_input_tokens;
    if (tokens) {
      $("contextValue").textContent = `${tokens.toLocaleString()} tok`;
      $("contextSub").textContent = (m.full_archive_model || "model") + " ? docs/FULL_ARCHIVE_RUN.md";
    } else {
      $("contextValue").textContent = "not recorded";
      $("contextSub").textContent = "run scripts/forensics_full_archive.py";
    }

    updateChart(m);
  }

  function ensureChart() {
    if (state.chart) return state.chart;
    if (typeof window.Chart === "undefined") return null;
    const canvas = $("trafficChart");
    if (!canvas) return null;

    const ctx = canvas.getContext("2d");
    state.chart = new window.Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "events",
            data: [],
            borderColor: "#39e1ff",
            backgroundColor: "rgba(57,225,255,0.10)",
            borderWidth: 1.6,
            pointRadius: 0,
            tension: 0.35,
            fill: true,
          },
          {
            label: "blocked",
            data: [],
            borderColor: "#ff5470",
            backgroundColor: "rgba(255,84,112,0.08)",
            borderWidth: 1.6,
            pointRadius: 0,
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            display: true,
            position: "top",
            align: "end",
            labels: {
              boxWidth: 8,
              boxHeight: 8,
              usePointStyle: true,
              color: "#7f91ab",
              font: { family: "JetBrains Mono, monospace", size: 9 },
            },
          },
          tooltip: {
            backgroundColor: "rgba(10,16,27,0.95)",
            borderColor: "rgba(86,130,190,0.35)",
            borderWidth: 1,
            titleFont: { family: "JetBrains Mono, monospace", size: 10 },
            bodyFont: { family: "JetBrains Mono, monospace", size: 10 },
          },
        },
        scales: {
          x: { display: false },
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              color: "#5d6f88",
              font: { family: "JetBrains Mono, monospace", size: 8 },
              maxTicksLimit: 3,
            },
            grid: { color: "rgba(86,130,190,0.10)" },
            border: { display: false },
          },
        },
      },
    });
    return state.chart;
  }

  function updateChart(m) {
    const chart = ensureChart();
    if (!chart) return; // Chart.js CDN unavailable: metrics still render

    const events = m.events_per_minute || [];
    if (!events.length) return;

    chart.data.labels = events.map((_, index) => `${index}`);
    chart.data.datasets[0].data = events;
    chart.data.datasets[1].data = m.blocked_per_minute || events.map(() => 0);
    chart.update("none");
  }

  async function loadMetrics() {
    state.metrics = await api("/api/metrics?window_seconds=300");
    renderMetrics();
  }

  function renderGateway() {
    const gw = state.gateway;
    const pill = $("gatewayPill");
    const body = $("gatewayBody");
    if (!gw) {
      pill.className = "pill";
      pill.textContent = "unknown";
      return;
    }
    if (!gw.reachable) {
      pill.className = "pill bad";
      pill.textContent = "offline";
      body.innerHTML = `<p class="muted">Target service on port 8001 is not reachable.</p>
        <p class="muted" style="margin-top:6px">${esc(gw.error || "")}</p>`;
      return;
    }

    pill.className = "pill ok";
    pill.textContent = `rev ${gw.revision ?? 0}`;

    const blocked = (gw.blocked_ips || []);
    const revoked = (gw.revoked_sessions || []);
    const rule = gw.rule;

    body.innerHTML = `
      <div class="gw-row"><span class="k">blocked IPs</span><span class="v">${blocked.length}</span></div>
      <div class="chips">${blocked.length
        ? blocked.map((ip) => `<span class="chip">${esc(ip)}</span>`).join("")
        : '<span class="chip neutral">none</span>'}</div>
      <div class="gw-row"><span class="k">revoked sessions</span><span class="v">${revoked.length}</span></div>
      <div class="chips">${revoked.length
        ? revoked.map((s) => `<span class="chip">${esc(s)}</span>`).join("")
        : '<span class="chip neutral">none</span>'}</div>
      <div class="gw-row"><span class="k">WAF rule</span><span class="v">${rule ? esc(rule.rule_id) : "not applied"}</span></div>
      <div class="gw-row"><span class="k">requests logged</span><span class="v">${gw.requests_total ?? 0}</span></div>`;
  }

  function renderEvents() {
    const feed = $("logFeed");
    const rows = state.events.slice(-MAX_LOG_ROWS).reverse();
    if (!rows.length) {
      feed.innerHTML = '<li><span class="t">--:--:--</span><span class="src">wait</span><span class="msg">no events yet</span></li>';
      return;
    }
    feed.innerHTML = rows.map((event) => `
      <li class="sev-${esc(event.severity || "info")}">
        <span class="t">${clock(event.timestamp)}</span>
        <span class="src">${esc(event.source)}</span>
        <span class="msg" title="${esc(event.summary)}">${esc(event.summary)}</span>
      </li>`).join("");
  }

  function statusLabel(status) {
    return {
      open: "open",
      contained: "contained",
      patched: "patched",
      dismissed: "dismissed",
    }[status] || status;
  }

  function classificationTone(classification) {
    if (!classification) return "warn";
    if (classification === "BENIGN_AUTHORIZED") return "ok";
    if (classification === "THREAT_CRITICAL" || classification === "GHOST_ATTACK") return "bad";
    return "warn";
  }

  function renderIncidents() {
    const host = $("incidentList");
    if (!state.incidents.length) {
      host.innerHTML = '<p class="muted">No incidents yet. Run a scenario on the left.</p>';
      return;
    }
    host.innerHTML = "";
    state.incidents.forEach((incident) => {
      const decision = incident.decision || {};
      const policy = incident.policy || {};
      const sev = (decision.severity || "info").toLowerCase();
      const pending = (policy.pending_actions || []).length;

      const card = document.createElement("article");
      card.className = "incident";
      card.dataset.sev = sev;
      card.innerHTML = `
        <div class="i-head">
          <span class="i-title">Scenario ${esc(incident.scenario || "?")} · ${esc(incident.id.slice(-6))}</span>
          <span class="status-tag ${esc(incident.status)}">${esc(statusLabel(incident.status))}</span>
        </div>
        <div class="i-meta">
          <span class="pill ${classificationTone(decision.classification)}">${esc(decision.classification || "—")}</span>
          <span class="pill">conf ${(decision.confidence ?? 0).toFixed(2)}</span>
          <span class="pill ${policy.mode === "approval" ? "warn" : policy.mode === "monitor" ? "" : "ok"}">${esc(policy.mode || "—")}</span>
          <span class="pill">${(incident.action_results || []).length} action(s)</span>
        </div>
        <p class="muted">${esc((decision.reasoning || "").slice(0, 190))}</p>
        <div class="i-actions"></div>`;

      const actions = card.querySelector(".i-actions");
      if (pending > 0) {
        const approve = document.createElement("button");
        approve.className = "btn";
        approve.textContent = `APPROVE ${pending}`;
        approve.addEventListener("click", () => approveIncident(incident.id, approve));
        actions.appendChild(approve);
      }
      const inspect = document.createElement("button");
      inspect.className = "btn";
      inspect.textContent = "INSPECT";
      inspect.addEventListener("click", () => loadIncident(incident.id));
      actions.appendChild(inspect);

      const analyze = document.createElement("button");
      analyze.className = "btn";
      analyze.textContent = incident.forensics ? "RE-ANALYZE" : "ANALYZE";
      analyze.addEventListener("click", () => runForensics(incident.id, analyze));
      actions.appendChild(analyze);

      if (incident.forensics) {
        const patch = document.createElement("button");
        patch.className = "btn";
        patch.textContent = incident.patch ? "RE-PATCH" : "PATCH";
        patch.addEventListener("click", () => runPatch(incident.id, patch));
        actions.appendChild(patch);
      }

      if (incident.status === "open") {
        const dismiss = document.createElement("button");
        dismiss.className = "btn danger";
        dismiss.textContent = "DISMISS";
        dismiss.addEventListener("click", () => dismissIncident(incident.id, dismiss));
        actions.appendChild(dismiss);
      }

      host.appendChild(card);
    });
  }

  function renderEvidence(incident) {
    const frame = $("frameImg");
    const framePlaceholder = $("framePlaceholder");
    const mask = $("maskImg");
    const maskPlaceholder = $("maskPlaceholder");
    const pill = $("visionPill");
    const note = $("visionNote");

    const vision = incident && incident.vision;
    if (!vision) {
      frame.hidden = true;
      framePlaceholder.hidden = false;
      mask.hidden = true;
      maskPlaceholder.hidden = false;
      pill.className = "pill";
      pill.textContent = "idle";
      note.textContent = "Trigger a scenario to capture physical evidence.";
      return;
    }

    const stamp = Date.now();
    const id = encodeURIComponent(incident.id);
    frame.src = `/api/incidents/${id}/frame?t=${stamp}`;
    frame.hidden = false;
    framePlaceholder.hidden = true;
    frame.onerror = () => { frame.hidden = true; framePlaceholder.hidden = false; framePlaceholder.textContent = "frame unavailable"; };

    mask.src = `/api/incidents/${id}/mask?t=${stamp}`;
    mask.hidden = false;
    maskPlaceholder.hidden = true;
    mask.onerror = () => { mask.hidden = true; maskPlaceholder.hidden = false; maskPlaceholder.textContent = "mask unavailable"; };

    const present = vision.operator_present;
    pill.className = `pill ${present ? "ok" : "bad"}`;
    pill.textContent = present ? "operator present" : "no operator";

    note.textContent = `${vision.model || "sam-3.1"} · confidence ${(vision.confidence ?? 0).toFixed(2)} · ROI [${(vision.roi || []).join(", ")}] · ${vision.description || ""}`;
  }

  function actionLine(result) {
    const ok = result.success ? "OK" : "FAIL";
    const tone = result.success ? "ok" : "bad";
    return `<span class="pill ${tone}">${ok}</span> ${esc(result.action)} → ${esc(result.target)}`;
  }

  function renderTimeline(incident) {
    const host = $("timeline");
    const label = $("timelineIncident");
    if (!incident) {
      label.textContent = "no incident";
      host.innerHTML = '<li class="empty">Observe → Orient → Decide → Act</li>';
      return;
    }

    const decision = incident.decision || {};
    const policy = incident.policy || {};
    const vision = incident.vision || {};
    const results = incident.action_results || [];
    const events = incident.events || [];
    label.textContent = `${incident.id} · ${ago(incident.created_at)}`;

    const steps = [];

    steps.push({
      kind: "obs",
      head: "Observe",
      body: `${events.length} correlated edge event(s): ${esc(events.map((e) => e.type).join(", ") || "none")}`,
      meta: events.slice(0, 3).map((e) => `<span class="pill">${esc(e.source)}</span>`).join(""),
    });

    steps.push({
      kind: "ori",
      head: "Orient",
      body: `operator_present=${vision.operator_present ? "true" : "false"} · ${esc(vision.description || "no camera evidence")} · ticket ${policy.ticket_id ? esc(policy.ticket_id) : "none"}`,
      meta: `<span class="pill ${vision.operator_present ? "ok" : "bad"}">camera ${(vision.confidence ?? 0).toFixed(2)}</span>`,
    });

    steps.push({
      kind: "dec",
      head: `Decide · ${esc(decision.model || "model")}`,
      body: `${esc(decision.classification || "—")} (severity ${esc(decision.severity || "—")}, confidence ${(decision.confidence ?? 0).toFixed(2)}) — ${esc(decision.reasoning || "")}`,
      meta: `<span class="pill ${classificationTone(decision.classification)}">${esc(decision.classification || "—")}</span>
             <span class="pill">${Math.round(decision.latency_ms || 0)} ms</span>`,
    });

    steps.push({
      kind: "pol",
      head: `Policy gate · ${esc(policy.mode || "—")}`,
      body: esc(policy.reason || "no policy verdict"),
      meta: `<span class="pill">${(policy.approved_actions || []).length} approved</span>
             <span class="pill ${((policy.pending_actions || []).length) ? "warn" : ""}">${(policy.pending_actions || []).length} pending</span>
             <span class="pill">${(policy.rate_limited_actions || []).length} rate-limited</span>`,
    });

    steps.push({
      kind: "act",
      head: "Act · MCP",
      body: results.length
        ? results.map((r) => actionLine(r)).join("<br/>")
        : (policy.pending_actions || []).length
          ? "waiting for human approval"
          : "no action executed",
      meta: results.length ? "" : '<span class="pill warn">no side effects</span>',
    });

    const forensics = incident.forensics;
    if (forensics) {
      steps.push({
        kind: "pol",
        head: `Cloud forensics ? ${esc(forensics.model || "model")}`,
        body: `${esc((forensics.summary || "").slice(0, 240))}`,
        meta: `<span class="pill ${forensics.citations_verified ? "ok" : "bad"}">${(forensics.citations || []).length} citation(s) ${forensics.citations_verified ? "verified" : "unverified"}</span>
               <span class="pill">${forensics.archive_lines_scanned || 0} lines</span>
               <span class="pill">${Math.round(forensics.latency_ms || 0)} ms</span>`,
      });
    }

    steps.push({
      kind: "gate",
      head: "Status",
      body: `incident ${esc(statusLabel(incident.status))}${incident.patch ? ` · patch ${esc(incident.patch.verification_note || "")}` : ""}`,
      meta: `<span class="status-tag ${esc(incident.status)}">${esc(statusLabel(incident.status))}</span>`,
    });

    host.innerHTML = steps.map((step) => `
      <li class="${step.kind === "act" ? "act" : step.kind === "gate" ? "gate" : ""}">
        <div class="t-head"><span>${step.head}</span></div>
        <div class="t-body">${step.body}</div>
        <div class="t-meta">${step.meta || ""}</div>
      </li>`).join("");
  }

  function renderAll() {
    renderBadges();
    renderStats();
    renderEvents();
    renderIncidents();
    renderTimeline(state.latest);
    renderEvidence(state.latest);
  }

  /* --------------------------------------------------------------- data load */

  async function loadConfig() {
    state.config = await api("/api/config");
    renderBadges();
  }

  async function loadSnapshot() {
    state.snapshot = await api("/api/state");
    renderBadges();
    renderStats();
  }

  async function loadEvents() {
    const body = await api("/api/events?limit=150");
    state.events = body.events || [];
    renderEvents();
  }

  async function loadIncidents() {
    const body = await api("/api/incidents?limit=50");
    state.incidents = body.incidents || [];
    renderIncidents();
  }

  async function loadGateway() {
    state.gateway = await api("/api/gateway");
    renderGateway();
  }

  async function loadScenarios() {
    const body = await api("/api/scenarios");
    renderScenarios(body.scenarios || []);
  }

  async function loadIncident(id) {
    const incident = await api(`/api/incidents/${encodeURIComponent(id)}`);
    state.latest = incident;
    renderTimeline(incident);
    renderEvidence(incident);
  }

  /* ----------------------------------------------------------------- actions */

  async function runScenario(id) {
    if (state.busy) return;
    state.busy = true;
    document.querySelectorAll(".scenario").forEach((btn) => { btn.disabled = true; });
    try {
      const incident = await api("/api/simulate", {
        method: "POST",
        body: JSON.stringify({ scenario: id }),
      });
      state.latest = incident;
      await Promise.all([loadEvents(), loadIncidents(), loadSnapshot(), loadGateway()]);
      renderTimeline(incident);
      renderEvidence(incident);
    } catch (error) {
      pushLocalEvent("error", `scenario ${id} failed: ${error.message}`);
    } finally {
      state.busy = false;
      document.querySelectorAll(".scenario").forEach((btn) => { btn.disabled = false; });
    }
  }

  async function approveIncident(id, button) {
    button.disabled = true;
    try {
      const incident = await api(`/api/incidents/${encodeURIComponent(id)}/approve`, {
        method: "POST",
      });
      state.latest = incident;
      await Promise.all([loadIncidents(), loadSnapshot(), loadGateway()]);
      renderTimeline(incident);
    } catch (error) {
      pushLocalEvent("error", `approval failed: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  }

  async function runForensics(id, button) {
    button.disabled = true;
    try {
      const incident = await api(`/api/incidents/${encodeURIComponent(id)}/forensics`, {
        method: "POST",
      });
      state.latest = incident;
      await loadIncidents();
      renderTimeline(incident);
    } catch (error) {
      pushLocalEvent("error", `forensics failed: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  }

  async function runPatch(id, button) {
    button.disabled = true;
    button.textContent = "PATCHING?";
    try {
      const incident = await api(`/api/incidents/${encodeURIComponent(id)}/patch`, {
        method: "POST",
      });
      state.latest = incident;
      await Promise.all([loadIncidents(), loadSnapshot(), loadGateway()]);
      renderTimeline(incident);
    } catch (error) {
      pushLocalEvent("error", `patch failed: ${error.message}`);
    } finally {
      button.disabled = false;
      button.textContent = "PATCH";
    }
  }

  async function dismissIncident(id, button) {
    button.disabled = true;
    try {
      const incident = await api(`/api/incidents/${encodeURIComponent(id)}/dismiss`, {
        method: "POST",
      });
      if (state.latest && state.latest.id === incident.id) {
        state.latest = incident;
        renderTimeline(incident);
      }
      await Promise.all([loadIncidents(), loadSnapshot()]);
    } catch (error) {
      pushLocalEvent("error", `dismiss failed: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  }

  function pushLocalEvent(severity, summary) {
    state.events.push({
      timestamp: new Date().toISOString(),
      source: "ui",
      severity,
      summary,
    });
    renderEvents();
  }

  /* --------------------------------------------------------------- websocket */

  function connect() {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${scheme}://${location.host}/ws`);
    state.ws = socket;

    socket.onopen = () => {
      state.wsConnected = true;
      state.retry = 0;
      renderBadges();
    };

    socket.onmessage = (message) => {
      let payload;
      try {
        payload = JSON.parse(message.data);
      } catch (_) {
        return;
      }
      if (payload.type === "hello") {
        state.snapshot = payload.state || state.snapshot;
        state.events = payload.events || state.events;
        renderAll();
      } else if (payload.type === "event") {
        state.events.push(payload.event);
        if (state.events.length > 500) state.events = state.events.slice(-500);
        renderEvents();
        loadSnapshot().catch(() => {});
      } else if (payload.type === "incident") {
        state.latest = payload.incident;
        renderTimeline(payload.incident);
        renderEvidence(payload.incident);
        loadIncidents().catch(() => {});
        loadMetrics().catch(() => {});
      } else if (payload.type === "state") {
        state.snapshot = payload.state || state.snapshot;
        renderStats();
        loadMetrics().catch(() => {});
      }
    };

    socket.onclose = () => {
      state.wsConnected = false;
      renderBadges();
      state.retry = Math.min(state.retry + 1, 6);
      setTimeout(connect, 700 * state.retry);
    };

    socket.onerror = () => {
      try { socket.close(); } catch (_) { /* ignore */ }
    };
  }

  /* -------------------------------------------------------------------- boot */

  function tickUptime() {
    const total = Math.floor((Date.now() - state.startedAt) / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    $("statUptime").textContent = `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  async function boot() {
    setInterval(tickUptime, 1000);
    tickUptime();

    try {
      await Promise.all([
        loadConfig(),
        loadSnapshot(),
        loadEvents(),
        loadIncidents(),
        loadGateway(),
        loadScenarios(),
        loadMetrics(),
      ]);
      const latest = state.incidents[0];
      if (latest) {
        state.latest = latest;
        renderTimeline(latest);
        renderEvidence(latest);
      } else {
        renderTimeline(null);
        renderEvidence(null);
      }
    } catch (error) {
      pushLocalEvent("error", `boot failed: ${error.message}`);
    }

    connect();
    setInterval(() => { loadGateway().catch(() => {}); }, 5000);
    setInterval(() => { loadSnapshot().catch(() => {}); }, 8000);
    setInterval(() => { loadMetrics().catch(() => {}); }, 5000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
