// The investigation screen: alert queue, agent trace, run details.
const SVG = (p) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${p}</svg>`;
const ICONS_EV = {
  reason: SVG('<path d="M9 18h6M10 21h4M12 3a6 6 0 00-4 10.5c.8.8 1 1.5 1 2.5h6c0-1 .2-1.7 1-2.5A6 6 0 0012 3z"/>'),
  tool: SVG('<path d="M14.7 6.3a4 4 0 00-5.4 5l-6 6 2.4 2.4 6-6a4 4 0 005-5.4l-2.6 2.6-2-2z"/>'),
  shield: SVG('<path d="M12 3l7 3v5c0 4.6-3 8.3-7 10-4-1.7-7-5.4-7-10V6l7-3z"/>'),
  person: SVG('<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>'),
  warn: SVG('<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/>'),
  check: SVG('<path d="M5 12l5 5 9-10"/>'),
  people: SVG('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-7 7-7s7 3 7 7M17 4a4 4 0 010 8"/>'),
  clock: SVG('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
};
const label = (s) => String(s).replaceAll("_", " ");
const shortMoney = (v) => v < 0.01 ? `$${v.toFixed(4)}` : `$${v.toFixed(3)}`;

function sevBadge(severity) {
  return `<span class="sev ${esc(severity)}"><i aria-hidden="true"></i>${esc(severity)}</span>`;
}

function ago(ts) {
  if (!ts) return "";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// --- Queue --------------------------------------------------------------------
let alertsCache = [], alertFilter = "all";

function visibleAlerts() {
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const list = alertsCache.filter((a) => alertFilter === "all" || (alertFilter === "new" && a.triage === "new")
    || (alertFilter === "critical" && a.severity_hint === "critical") || (alertFilter === "done" && !["new", "queued", "running"].includes(a.triage)));
  // What most needs a person comes first: untouched alerts, by severity, newest first.
  return list.sort((a, b) => (a.triage === "new" ? 0 : 1) - (b.triage === "new" ? 0 : 1)
    || (sevRank[a.severity_hint] ?? 9) - (sevRank[b.severity_hint] ?? 9) || (b.created_at || 0) - (a.created_at || 0));
}

function renderAlerts() {
  const box = $("#alerts"), top = box.scrollTop, focused = document.activeElement?.dataset?.id;
  const waiting = alertsCache.filter((a) => a.triage === "new").length;
  $("#alert-count").textContent = `${waiting} waiting · ${alertsCache.length} total`;
  const list = visibleAlerts();
  box.innerHTML = list.map((a) => `
    <button class="alert${a.id === selected ? " sel" : ""}" data-id="${esc(a.id)}">
      <span class="row">${sevBadge(a.severity_hint)}<span class="state${a.triage === "new" ? " fresh" : ""}">${esc(label(a.triage))}</span></span>
      <span class="t">${esc(a.title)}</span>
      <span class="m"><span>${esc(a.id)}</span>${a.created_at ? `<span>${esc(ago(a.created_at))}</span>` : ""}${a.occurrences > 1 ? `<span>seen ${Number(a.occurrences)}×</span>` : ""}</span>
    </button>`).join("") || '<p class="empty" style="padding:16px">Nothing here. Try another filter, or simulate an incident.</p>';
  box.scrollTop = top;
  box.querySelectorAll(".alert").forEach((el) => {
    el.onclick = () => selectAlert(el.dataset.id);
    if (el.dataset.id === focused) el.focus();
  });
}

async function loadAlerts() {
  alertsCache = await (await api("/api/alerts")).json();
  renderAlerts();
}

function showCase(alert) {
  $("#case-empty").hidden = true;
  $("#case").hidden = false;
  $("#case-sev").innerHTML = sevBadge(alert.severity_hint);
  $("#case-id").textContent = alert.id;
  $("#case-source").textContent = alert.source;
  $("#case-name").textContent = alert.title;
  $("#case-desc").textContent = alert.description;
  $("#case-entities").innerHTML = Object.entries(alert.entities || {}).filter(([, v]) => v)
    .map(([k, v]) => `<span class="entity">${esc(k)} <b>${esc(v)}</b></span>`).join("");
}

function selectAlert(id) {
  if (id === selected) return;
  selected = id;
  renderAlerts();
  const alert = alertsCache.find((a) => a.id === id);
  if (alert) showCase(alert);
  if (source) source.close();
  runId = null;
  stats = {};
  renderStats();
  $("#timeline").innerHTML = "";
  $("#go").disabled = false;
  highlight(null);
  openLatestRun(id);
}

// An alert that's been investigated opens on its latest run, so the answer is one click away.
async function openLatestRun(id) {
  const runs = await (await api("/api/runs")).json();
  if (selected !== id) return;  // someone clicked another alert while this loaded
  const latest = runs.find((r) => r.alert_id === id);
  if (latest) { watch(latest.id); return; }
  $("#timeline").innerHTML = '<p class="empty case-hint">Not investigated yet. Choose how to run it, then start the investigation.</p>';
}

$("#filters").onclick = (ev) => {
  const chip = ev.target.closest(".chip");
  if (!chip) return;
  alertFilter = chip.dataset.filter;
  document.querySelectorAll("#filters .chip").forEach((c) => c.classList.toggle("on", c === chip));
  renderAlerts();
};

$("#generate").onclick = async () => {
  const res = await api("/api/alerts/generate", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario: $("#scenario").value || null }) });
  const body = await res.json();
  const msg = $("#generate-msg");
  msg.className = res.ok ? "msg" : "msg err";
  msg.textContent = !res.ok ? (body.error || body.detail) : body.new ? `Created ${body.alert.id}.` : `Added to ${body.alert.id}: same incident.`;
  await loadAlerts();
  if (res.ok && body.alert) selectAlert(body.alert.id);
};

// --- Run details ----------------------------------------------------------------
function highlight(stage) {
  document.querySelectorAll("#stages li").forEach((li) => li.classList.toggle("on", li.dataset.stage === stage));
}

function renderStats() {
  const rows = Object.entries(stats).map(([k, v]) => `<div class="stat"><span>${esc(k)}</span><b>${esc(v)}</b></div>`);
  $("#stats").innerHTML = rows.join("") || '<p class="empty">Nothing running yet.</p>';
}

// --- Trace ----------------------------------------------------------------------
let eventAgent = null;
const toolRows = {};

function nearBottom() {
  const pane = document.querySelector(".work-pane");
  return pane.scrollHeight - pane.scrollTop - pane.clientHeight < 200;
}

function add(cls, icon, head, body = "") {
  const follow = nearBottom();  // don't drag someone away from what they're reading
  const div = document.createElement("div");
  div.className = `ev ${cls}`;
  const who = eventAgent ? `<span class="tag agent">${esc(eventAgent)}</span>` : "";
  div.innerHTML = `<div class="ev-icon">${ICONS_EV[icon]}</div><div class="ev-body"><div class="ev-head">${who}${head}</div>${body}</div>`;
  $("#timeline").appendChild(div);
  if (follow) { const pane = document.querySelector(".work-pane"); pane.scrollTop = pane.scrollHeight; }
  return div;
}

const fold = (title, value) => `<details><summary>${esc(title)}</summary><pre>${esc(JSON.stringify(value, null, 2))}</pre></details>`;

function summarizeOutput(tool, output) {
  if (!output) return "";
  if (typeof output.count === "number") return `${output.count} log ${output.count === 1 ? "entry" : "entries"}`;
  if (Array.isArray(output.matches)) return output.matches.length ? `${output.matches.length} past ${output.matches.length === 1 ? "case" : "cases"}` : "no past cases";
  if (output.reputation) return `reputation: ${output.reputation}`;
  if (output.status) return output.status;
  if (output.description) return output.description;
  if (output.criticality) return `criticality: ${output.criticality}`;
  if (output.title) return output.title;
  return "";
}

function renderReport(e) {
  const r = e.report;
  const list = (items) => `<ul>${(items || []).map((x) => `<li>${esc(x)}</li>`).join("") || "<li>None</li>"}</ul>`;
  const div = document.createElement("div");
  div.className = "report";
  div.innerHTML = `
    <div class="report-head"><h3>${esc(label(r.verdict))}</h3>${sevBadge(r.severity)}<span class="techniques">${(r.mitre_techniques || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</span></div>
    <div class="report-text">${esc(r.summary)}</div>
    <h4>Recommendations</h4>${list(r.recommendations)}
    ${r.limitations ? `<h4>Not checked / limitations</h4>${list(r.limitations)}` : ""}
    <h4>Actions taken</h4><ul>${e.actions.map((a) => `<li>${esc(label(a.action))}: <code>${esc(a.target)}</code></li>`).join("") || "<li>None</li>"}</ul>`;
  $("#timeline").appendChild(div);
  const pane = document.querySelector(".work-pane");
  div.scrollIntoView({ block: "nearest" });
  return pane;
}

function handle(e) {
  eventAgent = e.agent && e.agent !== "coordinator" ? e.agent : null;  // only specialists need a label
  switch (e.kind) {
    case "queued":
      add("", "clock", "Waiting for a free worker"); break;
    case "start":
      add("", "clock", `Picked up by ${esc(e.worker || "a worker")}`, e.attempt > 1 ? `<div class="note">Attempt ${Number(e.attempt)}</div>` : "");
      stats = { Status: "Running", Mode: e.mode === "live" ? "Live AI" : "Demo (scripted)", Architecture: e.architecture === "multi" ? "Specialists" : "Single agent", Loops: 0, "Tool calls": 0 };
      renderStats(); break;
    case "step": {
      const s = document.createElement("div");
      s.className = "step-label";
      s.textContent = `${e.agent && e.agent !== "coordinator" ? `${e.agent} · ` : ""}Loop ${e.n}`;
      $("#timeline").appendChild(s);
      stats.Loops = (stats.Loops || 0) + 1; renderStats(); break;
    }
    case "reason":
      highlight("reason");
      add("reason", "reason", e.source === "scripted" ? 'Reasoning <span class="tag">scripted</span>' : "Reasoning", `<div class="ev-text">${esc(e.text)}</div>`); break;
    case "act": {
      highlight("act");
      stats["Tool calls"] = (stats["Tool calls"] || 0) + 1; renderStats();
      const row = add("", "tool", `<code>${esc(e.tool)}</code>${e.risk === "write" ? '<span class="tag">changes something</span>' : ""}`, `<div class="note result" hidden></div>${fold("Details", e.input)}`);
      if (e.tool_use_id) toolRows[e.tool_use_id] = row;
      break;
    }
    case "observe": {
      highlight("observe");
      const row = toolRows[e.tool_use_id];
      if (e.tool === "submit_triage_report" || e.tool === "submit_findings" || !row) break;
      const note = row.querySelector(".result");
      const cached = e.cache && e.cache !== "miss" ? " · from cache" : "";
      note.textContent = `${summarizeOutput(e.tool, e.output)}${cached}`;
      note.hidden = !note.textContent;
      row.querySelector(".ev-body").insertAdjacentHTML("beforeend", fold("Result", e.output));
      break;
    }
    case "policy":
      if (e.decision === "allow") break;
      highlight("policy");
      if (e.decision === "deny") {
        add("denied", "shield", "Blocked by policy", `<div class="ev-text">${esc(e.reason)}</div>`);
        stats.Blocked = (stats.Blocked || 0) + 1; renderStats();
      }
      break;
    case "approval_request": {
      highlight("human");
      const allowed = me.approvable_tools.includes(e.tool);
      const { reason, ...target } = e.input || {};
      const wrap = document.createElement("div");
      wrap.className = "ev";
      wrap.innerHTML = `<div class="ev-icon">${ICONS_EV.person}</div><div class="ev-body"><div class="callout ask">
        <div class="ev-head">Your decision is needed</div>
        <div class="ask-action">${esc(label(e.tool))}: <code>${esc(Object.values(target).join(", "))}</code></div>
        ${reason ? `<div class="why">${esc(reason)}</div>` : ""}
        ${allowed ? '<div class="approve"><button class="btn good yes">Approve</button><button class="btn danger no">Deny</button></div>'
                  : `<div class="note">Your role (${esc(me.role)}) can't decide this. Waiting for an analyst who can.</div>`}
        <div class="note approve-msg" hidden></div></div></div>`;
      $("#timeline").appendChild(wrap);
      wrap.scrollIntoView({ block: "center" });
      if (!allowed) break;
      const answer = async (approved) => {
        wrap.querySelectorAll("button").forEach((b) => b.disabled = true);
        const res = await api(`/api/runs/${runId}/approve`, { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tool_use_id: e.tool_use_id, approved }) });
        if (!res.ok) { const m = wrap.querySelector(".approve-msg"); m.hidden = false; m.textContent = (await res.json()).detail; }
      };
      wrap.querySelector(".yes").onclick = () => answer(true);
      wrap.querySelector(".no").onclick = () => answer(false);
      break;
    }
    case "approval_result":
      add(e.approved ? "done" : "denied", e.approved ? "check" : "shield", e.note ? "Not approved" : `${e.approved ? "Approved" : "Denied"} by ${esc(e.decided_by || "analyst")}`, e.note ? `<div class="ev-text">${esc(e.note)}</div>` : "");
      break;
    case "guardrail":
      highlight("policy");
      add("guardrail", "warn", "Possible prompt injection", `<div class="callout guard" style="margin-top:4px"><div>${esc(e.finding)}. It's treated as data, not as instructions.</div>${fold("Matched patterns", e.patterns)}</div>`);
      stats["Injection flags"] = (stats["Injection flags"] || 0) + 1; renderStats();
      break;
    case "findings":
      add("done", "people", `Findings from ${esc(e.specialist)}${e.reused ? ' <span class="tag">saved earlier</span>' : ""}`, `<div class="ev-text">${esc(e.findings.summary)}</div>${fold("Evidence and gaps", e.findings)}`);
      break;
    case "specialist_failed":
      add("denied", "warn", `${esc(e.specialist)} returned no findings`, `<div class="ev-text">${esc(e.reason)}. The coordinator treats this as a gap.</div>`); break;
    case "usage":
      stats["Tokens in / out"] = `${(parseInt(String(stats["Tokens in / out"] || "0").split(" / ")[0]) || 0) + e.input + e.cache_read} / ${(parseInt(String(stats["Tokens in / out"] || "0 / 0").split(" / ")[1]) || 0) + e.output}`;
      stats.Model = e.model; stats["Estimated cost"] = shortMoney(e.run_cost_usd); renderStats(); break;
    case "resume":
      add("done", "check", `Resuming from loop ${Number(e.from_step)}`, '<div class="note">Earlier loops were saved, so they aren\'t repeated.</div>'); break;
    case "idempotent":
      add("done", "check", `Already done: <code>${esc(e.tool)}</code>`, '<div class="note">This action finished in an earlier attempt, so its saved result is reused. Nothing ran twice.</div>'); break;
    case "deferred":
      add("", "clock", "Paused: provider unavailable", `<div class="ev-text">${esc(e.message)}. This doesn't use up a retry.</div>`); break;
    case "retry":
      add("denied", "warn", `Attempt ${Number(e.attempt)} failed`, `<div class="ev-text">${esc(e.error)}\nIt's back on the queue for a retry.</div>`); break;
    case "final":
      highlight(null);
      stats.Status = "Report ready"; renderStats();
      renderReport(e); break;
    case "error":
      stats.Status = "Stopped"; renderStats();
      add("denied", "warn", "Stopped", `<div class="ev-text">${esc(e.message)}</div>`); break;
    case "end":
      highlight(null);
      $("#go").disabled = !selected;
      loadHistory(); loadAlerts(); break;
  }
}

let source = null;
function watch(id) {
  if (source) source.close();
  runId = id;
  stats = {};
  renderStats();
  $("#timeline").innerHTML = "";
  source = new EventSource(`/api/runs/${id}/events`);
  source.onmessage = (m) => { const e = JSON.parse(m.data); handle(e); if (e.kind === "end") source.close(); };
}

async function loadHistory() {
  const runs = await (await api("/api/runs")).json();
  if (!runs.length) return;
  $("#history").innerHTML = runs.slice(0, 8).map((r) => `
    <button class="hist" data-id="${esc(r.id)}" data-alert="${esc(r.alert_id)}">
      <b>${esc(r.alert_id)} · ${esc(label(r.verdict || r.status))}</b>
      ${esc(ago(r.created_at))} · ${esc(r.mode)}${r.architecture === "multi" ? " · specialists" : ""} · ${esc(r.started_by || "?")}
    </button>`).join("");
  document.querySelectorAll(".hist").forEach((el) => el.onclick = () => {
    selected = el.dataset.alert;
    renderAlerts();
    const alert = alertsCache.find((a) => a.id === selected);
    if (alert) showCase(alert);
    watch(el.dataset.id);
  });
}

const chosen = (name) => document.querySelector(`input[name=${name}]:checked`).value;

$("#go").onclick = async () => {
  $("#go").disabled = true;
  const res = await api("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alert_id: selected, mode: chosen("mode"), architecture: chosen("architecture") }) });
  const body = await res.json();
  if (!res.ok) {
    $("#timeline").innerHTML = "";
    eventAgent = null;
    const title = { 403: "Not allowed", 429: "Too many runs", 503: "Queue is full" }[res.status] || "Couldn't start";
    const after = res.headers.get("Retry-After");
    add("denied", "warn", title, `<div class="ev-text">${esc(body.error || body.detail)}${after ? ` Try again in ${esc(after)}s.` : ""}</div>`);
    $("#go").disabled = false;
    return;
  }
  watch(body.run_id);
  loadHistory();
};

async function loadQueue() {
  try {
    const q = await (await api("/api/queue")).json();
    const workers = q.busy_workers.length ? q.busy_workers.map(esc).join(", ") : "none busy";
    $("#queue").innerHTML = ["queued", "leased", "done", "dead"].map((k) =>
      `<div class="stat"><span>${k === "leased" ? "in progress" : k === "dead" ? "failed permanently" : k}</span><b>${q[k]}</b></div>`).join("")
      + `<div class="stat"><span>busy workers</span><b>${workers}</b></div>`;
  } catch { /* server restarting */ }
}

async function loadCache() {
  try {
    const c = await (await api("/api/cache")).json();
    $("#cache").innerHTML = [
      ["hit ratio", c.hit_ratio === null ? "-" : Math.round(c.hit_ratio * 100) + "%"],
      ["external calls avoided", c.origin_calls_avoided], ["time saved", c.seconds_saved + " s"],
    ].map(([k, v]) => `<div class="stat"><span>${k}</span><b>${esc(v)}</b></div>`).join("");
  } catch { /* server restarting */ }
}
$("#flush").onclick = async () => {
  await api("/api/cache/invalidate", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  loadCache();
};
