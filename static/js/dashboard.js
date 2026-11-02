// The analytics dashboard. This file and css/dashboard.css own everything inside #obs.
// Only obsTimer, showDashboard and loadTrace are global; the rest stays private so names can't clash with other scripts.
let obsTimer = null;

const obsDashboard = (() => {
  // A fixed frame: regions are filled in place, so a refresh can't lose scroll, filters, open panels or focus.
  const MARKUP = `
  <div class="db">
    <div class="db-head">
      <h2 class="db-title">Analytics <span class="db-sub">Last 24 hours</span></h2>
      <p class="db-status" id="db-status"></p>
    </div>
    <p class="db-banner" id="db-demo-banner" hidden></p>

    <div class="db-attention">
      <section class="db-card" aria-labelledby="db-h-attention">
        <h3 id="db-h-attention">Needs attention</h3>
        <div id="db-alerts" aria-live="polite"></div>
      </section>
      <section class="db-card" aria-labelledby="db-h-next">
        <h3 id="db-h-next">Next to triage <span class="db-sub">Worst and oldest first</span></h3>
        <div id="db-next"></div>
      </section>
    </div>

    <div class="db-kpis" id="db-kpis"></div>

    <div class="db-charts">
      <section class="db-card" aria-labelledby="db-h-activity">
        <h3 id="db-h-activity">Are we keeping up? <span class="db-sub" id="db-activity-sub"></span></h3>
        <div id="db-activity"></div>
        <details class="db-tableview"><summary>View as table</summary><div class="db-scroll" id="db-activity-table"></div></details>
      </section>
      <section class="db-card" aria-labelledby="db-h-outcomes">
        <h3 id="db-h-outcomes">Outcomes <span class="db-sub">Live and demo kept apart</span></h3>
        <div id="db-outcomes"></div>
        <details class="db-tableview"><summary>View as table</summary><div class="db-scroll" id="db-outcomes-table"></div></details>
        <div class="db-accuracy" id="db-accuracy"></div>
      </section>
    </div>

    <section class="db-card" aria-labelledby="db-h-runs">
      <h3 id="db-h-runs">Investigations <span class="db-sub">Select one to open its trace</span></h3>
      <form class="db-filters" id="db-filters" role="search" aria-label="Filter investigations">
        <label class="db-field db-field-grow">Search<input type="search" id="db-f-q" placeholder="Alert, title, analyst or run" autocomplete="off"></label>
        <label class="db-field">Severity<select id="db-f-severity">
          <option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select></label>
        <label class="db-field">Outcome<select id="db-f-outcome">
          <option value="">All</option><option value="true_positive">True positive</option><option value="false_positive">False positive</option>
          <option value="needs_escalation">Needs escalation</option><option value="failed">Failed</option><option value="active">In progress</option>
        </select></label>
        <label class="db-field">Run type<select id="db-f-mode">
          <option value="">All</option><option value="live">Live</option><option value="demo">Demo</option>
        </select></label>
        <p class="db-count" id="db-run-count" role="status"></p>
      </form>
      <div class="db-scroll db-runs" id="db-runs"></div>
      <div class="db-runs-foot" id="db-runs-foot"></div>
    </section>

    <section class="db-card" id="db-trace-card" aria-labelledby="db-trace-title" hidden>
      <div class="db-trace-head">
        <div>
          <h3 id="db-trace-title" tabindex="-1">Trace</h3>
          <p class="db-sub" id="db-trace-meta"></p>
        </div>
        <button type="button" class="db-btn" id="db-trace-close">Close trace</button>
      </div>
      <div id="db-trace"></div>
      <details class="db-tableview"><summary>View as table</summary><div class="db-scroll" id="db-trace-table"></div></details>
    </section>

    <section class="db-detail" aria-labelledby="db-h-detail">
      <h3 id="db-h-detail">System detail</h3>
      <p class="db-note">Demo decisions and timings are scripted, so don't compare demo time or calls as results. Compare live runs.</p>
      <div class="db-panels">
        <details class="db-panel" open><summary><span>Safety and access</span><span class="db-gist" id="db-g-safety"></span></summary><div class="db-scroll" id="db-p-safety"></div></details>
        <details class="db-panel" open><summary><span>Single vs multi-agent</span><span class="db-gist" id="db-g-compare"></span></summary><div class="db-scroll" id="db-p-compare"></div></details>
        <details class="db-panel"><summary><span>Latency</span><span class="db-gist" id="db-g-latency"></span></summary><div class="db-scroll" id="db-p-latency"></div></details>
        <details class="db-panel"><summary><span>Tools</span><span class="db-gist" id="db-g-tools"></span></summary><div class="db-scroll" id="db-p-tools"></div></details>
        <details class="db-panel"><summary><span>Models</span><span class="db-gist" id="db-g-models"></span></summary><div class="db-scroll" id="db-p-models"></div></details>
        <details class="db-panel"><summary><span>Agents</span><span class="db-gist" id="db-g-agents"></span></summary><div class="db-scroll" id="db-p-agents"></div></details>
        <details class="db-panel"><summary><span>Model provider</span><span class="db-gist" id="db-g-provider"></span></summary><div class="db-scroll" id="db-p-provider"></div></details>
        <details class="db-panel"><summary><span>Reliability</span><span class="db-gist" id="db-g-reliability"></span></summary><div class="db-scroll" id="db-p-reliability"></div></details>
        <details class="db-panel"><summary><span>Alert queue</span><span class="db-gist" id="db-g-queue"></span></summary><div class="db-scroll" id="db-p-queue"></div></details>
      </div>
      <p class="db-foot">Scrapers read <code>/metrics</code> with a service token, not a login. JSON logs are in <code>logs/</code>.</p>
    </section>
  </div>`;

  // --- formatting ---------------------------------------------------------
  const el = (id) => document.getElementById(id);
  const secs = (s) => s === null || s === undefined ? "-" : s < 1 ? `${Math.round(s * 1000)} ms` : s < 120 ? `${s.toFixed(1)} s` : s < 7200 ? `${(s / 60).toFixed(1)} min` : `${(s / 3600).toFixed(1)} h`;
  const usd = (v) => v === null || v === undefined ? "-" : v === 0 ? "$0.00" : v < 1 ? `$${v.toFixed(3)}` : `$${v.toFixed(2)}`;
  const num = (v) => Number(v || 0).toLocaleString();
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const age = (s) => s < 90 ? "under 2 min" : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
  const plural = (n, word) => `${num(n)} ${word}${n === 1 ? "" : "s"}`;
  const words = (s) => String(s).replaceAll("_", " ");
  const capital = (s) => { const t = words(s); return t.charAt(0).toUpperCase() + t.slice(1); };

  // Status icons differ by shape as well as color. The glyph is a cut-out, so it works on any surface in either theme.
  const SHAPES = {
    critical: "M5 1h6l4 4v6l-4 4H5l-4-4V5zM7 4v5h2V4zM7 10.5v2h2v-2z",
    serious: "M8 .5 15.5 8 8 15.5 .5 8zM7 4v5h2V4zM7 10v2h2v-2z",
    warning: "M8 1l7.5 13.5H.5zM7 6v4.5h2V6zM7 11.5v2h2v-2z",
    good: "M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm3.6 4.2-5.5 5.5-2.3-2.3 1.1-1.1 1.2 1.2 4.4-4.4z",
    neutral: "M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm0 3.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7z",
  };
  const icon = (level) => `<svg class="db-icon db-${SHAPES[level] ? level : "neutral"}" viewBox="0 0 16 16" aria-hidden="true"><path fill-rule="evenodd" d="${SHAPES[level] || SHAPES.neutral}"/></svg>`;
  const state = (level, text) => `<span class="db-state">${icon(level)}${esc(text)}</span>`;
  const SEVERITY_LEVEL = { critical: "critical", high: "serious", medium: "warning", low: "neutral" };
  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
  const severityTag = (s) => s ? state(SEVERITY_LEVEL[s] || "neutral", capital(s)) : '<span class="db-muted">-</span>';

  const table = (heads, rows, empty) => rows.length
    ? `<table class="db-table"><thead><tr>${heads.map((h) => `<th scope="col" class="${h[1] || ""}">${esc(h[0])}</th>`).join("")}</tr></thead><tbody>${rows.map((r) =>
        `<tr>${r.map((c, i) => `<td class="${heads[i][1] || ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`
    : `<p class="db-empty">${esc(empty)}</p>`;
  const emptyNote = (title, how) => `<div class="db-empty-box"><b>${esc(title)}</b><span>${esc(how)}</span></div>`;

  // --- in-place updates ---------------------------------------------------
  const rendered = new Map();

  // Replace a region only when its content changed, and put keyboard focus back where it was.
  function put(id, html) {
    if (rendered.get(id) === html) return;
    const region = el(id), active = document.activeElement;
    const key = active && region.contains(active) ? active.dataset.fk : null;
    region.innerHTML = html;
    rendered.set(id, html);
    if (key) {
      const next = region.querySelector(`[data-fk="${CSS.escape(key)}"]`);
      if (next) { next.tabIndex = 0; next.focus({ preventScroll: true }); }
    }
  }

  // --- tooltip ------------------------------------------------------------
  let tips = {};  // key -> what to show. Filled on render; everything goes in through textContent because labels are data.

  function tipEl() {
    let tip = $("#tip");
    if (!tip) { tip = document.createElement("div"); tip.id = "tip"; tip.hidden = true; document.body.appendChild(tip); }
    return tip;
  }

  function showTip(key, x, y) {
    const data = tips[key];
    if (!data) return;
    const tip = tipEl();
    tip.textContent = "";
    const head = document.createElement("b");
    head.textContent = data.title;
    tip.appendChild(head);
    for (const [name, value, color] of data.rows) {
      const row = document.createElement("div"); row.className = "db-tip-row";
      if (color) { const k = document.createElement("i"); k.style.background = color; row.appendChild(k); }
      const v = document.createElement("strong"); v.textContent = value;
      const n = document.createElement("span"); n.textContent = name;
      row.append(v, n);
      tip.appendChild(row);
    }
    tip.hidden = false;
    const box = tip.getBoundingClientRect();
    tip.style.left = `${Math.max(8, Math.min(x + 12, innerWidth - box.width - 8))}px`;
    tip.style.top = `${Math.max(8, y + 12 + box.height > innerHeight ? y - box.height - 12 : y + 12)}px`;
  }
  const hideTip = () => { const tip = $("#tip"); if (tip) tip.hidden = true; };

  // --- needs attention, KPIs ----------------------------------------------
  const LEVEL_ORDER = { critical: 0, serious: 1, warning: 2 };

  function renderAttention(s) {
    const rules = [...s.alerts].sort((a, b) => (LEVEL_ORDER[a.level] ?? 3) - (LEVEL_ORDER[b.level] ?? 3));
    put("db-alerts", rules.length
      ? `<ul class="db-rules">${rules.map((a) => `<li class="db-rule db-rule-${esc(a.level)}">
          <span class="db-rule-level">${state(a.level, capital(a.level))}</span>
          <div><b>${esc(a.title)}</b><p>${esc(a.detail)}</p></div></li>`).join("")}</ul>`
      : `<div class="db-rule db-rule-good"><span class="db-rule-level">${state("good", "All clear")}</span><div><b>Nothing needs attention.</b><p>No alert rule fired in the last 24 hours. Rules cover stuck alerts, stalled jobs, provider trouble, budget and access.</p></div></div>`);
    const next = s.triage.next_up;
    put("db-next", next.length
      ? `<ul class="db-next">${next.map((a) => `<li data-open-alert="${esc(a.id)}" role="button" tabindex="0" aria-label="Open ${esc(a.id)}">
          <span class="db-next-sev">${severityTag(a.severity)}</span>
          <span class="db-next-main"><b>${esc(a.id)}</b> ${esc(a.title)}${a.occurrences > 1 ? ` <span class="db-muted">x${esc(a.occurrences)}</span>` : ""}</span>
          <span class="db-next-age">${esc(age(a.age_seconds))}</span></li>`).join("")}</ul>
        ${s.alert_queue.waiting > next.length ? `<p class="db-foot">and ${esc(num(s.alert_queue.waiting - next.length))} more in the alert queue.</p>` : '<p class="db-foot">Select one to open it.</p>'}`
      : emptyNote("No alerts are waiting.", "Generate one on the agent page, or stream them with ALERT_EVERY_SECONDS."));
  }

  function tile(label, value, note, opts = {}) {
    return `<section class="db-card db-kpi" aria-label="${esc(label)}"><div class="db-kpi-label">${opts.level ? icon(opts.level) : ""}${esc(label)}</div>
      <div class="db-kpi-value">${esc(value)}</div>${opts.extra || ""}<div class="db-kpi-note">${esc(note)}</div></section>`;
  }

  function renderKpis(s) {
    const { waiting_by_severity: bySeverity, time_to_triage: ttt, outcomes } = s.triage;
    const waiting = s.alert_queue.waiting;
    const breakdown = Object.entries(bySeverity).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ");
    const tiles = [tile("Alerts waiting", num(waiting), waiting ? breakdown : "The queue is clear")];

    const critical = bySeverity.critical || 0;
    tiles.push(tile("Critical waiting", num(critical), critical ? `Oldest has waited ${age(s.alert_queue.oldest_critical_age)}` : "None waiting", critical ? { level: "critical" } : {}));

    tiles.push(ttt.live.count
      ? tile("Median time to triage", secs(ttt.live.median_seconds), `Alert raised to verdict, ${plural(ttt.live.count, "live run")}`)
      : ttt.demo.count
        ? tile("Median time to triage", secs(ttt.demo.median_seconds), `Scripted demo, ${plural(ttt.demo.count, "run")}. Not a result`)
        : tile("Median time to triage", "-", "No completed runs on generated alerts yet"));

    const finished = (o) => o.true_positive + o.false_positive + o.needs_escalation + o.no_verdict + o.failed;
    const liveDone = finished(outcomes.live), demoDone = finished(outcomes.demo);
    if (liveDone) {
      tiles.push(tile("Run success", `${Math.round((liveDone - outcomes.live.failed) / liveDone * 100)}%`,
        `${liveDone - outcomes.live.failed} of ${liveDone} live${demoDone ? `. ${demoDone} demo not counted` : ""}`));
    } else if (demoDone) {
      tiles.push(tile("Run success", `${Math.round((demoDone - outcomes.demo.failed) / demoDone * 100)}%`, `${demoDone - outcomes.demo.failed} of ${demoDone}, all scripted demo`));
    } else {
      tiles.push(tile("Run success", "-", "No finished runs yet"));
    }

    const budget = s.daily_budget_usd, share = budget ? s.cost_usd / budget : 0;
    const level = share >= 1 ? "critical" : share >= 0.8 ? "warning" : null;
    const meter = budget ? `<div class="db-meter${level ? ` db-meter-${level}` : ""}" role="meter" aria-label="Daily budget used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.min(100, Math.round(share * 100))}"><i style="width:${share > 0 ? `max(2px, ${Math.min(100, share * 100)}%)` : 0}"></i></div>` : "";
    tiles.push(tile("Estimated model spend", usd(s.cost_usd),
      budget ? `of ${usd(budget)} daily budget${level === "critical" ? ": used up" : level ? ": nearly used" : ""}` : "No daily budget set",
      { extra: meter, ...(level ? { level } : {}) }));
    put("db-kpis", tiles.join(""));
  }

  // --- activity -----------------------------------------------------------
  const ACTIVITY = [["alerts", "Alerts raised", "var(--series-1)"], ["runs", "Runs started", "var(--series-2)"]];

  function niceTicks(peak) {
    const steps = [];
    for (let p = 1; p <= 1e6; p *= 10) steps.push(p, 2 * p, 5 * p);
    const step = steps.find((v) => v * 2 >= peak);
    return [0, step, step * 2];
  }

  function renderActivity(s) {
    const hours = s.triage.activity;
    const alerts = hours.reduce((n, h) => n + h.alerts, 0), runs = hours.reduce((n, h) => n + h.runs, 0);
    el("db-activity-sub").textContent = `${plural(alerts, "alert")} raised, ${plural(runs, "run")} started`;
    const busy = hours.filter((h) => h.alerts || h.runs);
    put("db-activity-table", table([["Hour starting"], ["Alerts raised", "n"], ["Critical", "n"], ["Runs started", "n"]],
      busy.map((h) => [clock(h.hour), h.alerts, h.critical, h.runs]), "No activity in the last 24 hours.")
      + (busy.length ? '<p class="db-foot">Hours not listed had no activity.</p>' : ""));
    el("db-activity-table").closest("details").hidden = !busy.length;
    if (!busy.length) {
      put("db-activity", emptyNote("No alerts or runs in the last 24 hours.", "Generate an alert on the agent page and start a run. Each hour's arrivals and runs appear here."));
      return;
    }
    const ticks = niceTicks(Math.max(...hours.map((h) => Math.max(h.alerts, h.runs))));
    const top = ticks[2];
    hours.forEach((h, i) => {
      tips[`hour:${i}`] = { title: i === hours.length - 1 ? `${clock(h.hour)}, this hour so far` : `${clock(h.hour)} hour`,
        rows: [[`alerts raised${h.critical ? `, ${h.critical} critical` : ""}`, num(h.alerts), ACTIVITY[0][2]], ["runs started", num(h.runs), ACTIVITY[1][2]]] };
    });
    const bar = (value, color) => value ? `<i class="db-bar" style="height:${value / top * 100}%;background:${color}"></i>` : "";
    const slots = hours.map((h, i) => `<div class="db-hour" data-tip="hour:${i}" data-fk="hour-${h.hour}" data-rove tabindex="${i === hours.length - 1 ? 0 : -1}"
        role="img" aria-label="${esc(clock(h.hour))}: ${h.alerts} alerts raised, ${h.critical} critical, ${h.runs} runs started">${bar(h.alerts, ACTIVITY[0][2])}${bar(h.runs, ACTIVITY[1][2])}</div>`).join("");
    const labels = hours.map((h, i) => {
      const last = i === hours.length - 1;
      return `<span class="db-xlabel${last ? " db-xlabel-end" : ""}">${(hours.length - 1 - i) % 6 === 0 ? `<em>${last ? "Now" : esc(clock(h.hour))}</em>` : ""}</span>`;
    }).join("");
    put("db-activity", `
      <div class="db-legend">${ACTIVITY.map(([, name, color]) => `<span><i style="background:${color}"></i>${esc(name)}</span>`).join("")}</div>
      <div class="db-chart" role="group" aria-label="${esc(`Alerts raised and runs started per hour, last 24 hours. ${alerts} alerts, ${runs} runs. Use the left and right arrow keys to read each hour.`)}">
        <div class="db-yaxis" aria-hidden="true">${ticks.map((t) => `<span style="bottom:${t / top * 100}%">${esc(num(t))}</span>`).join("")}</div>
        <div class="db-plot">${ticks.map((t) => `<i class="db-grid" style="bottom:${t / top * 100}%"></i>`).join("")}${slots}</div>
        <div class="db-xaxis" aria-hidden="true">${labels}</div>
      </div>`);
  }

  // --- outcomes -----------------------------------------------------------
  const PARTS = [["true_positive", "true positive", "var(--series-1)"], ["false_positive", "false positive", "var(--series-2)"],
    ["needs_escalation", "needs escalation", "var(--series-3)"], ["failed", "failed", "var(--series-4)"], ["no_verdict", "no verdict", "var(--series-muted)"]];

  function renderOutcomes(s) {
    const acc = s.alert_queue.accuracy;
    put("db-accuracy", acc.runs
      ? `<div class="db-accuracy-label">Live verdict accuracy</div>
         <div class="db-accuracy-value">${esc(`${acc.correct} of ${acc.runs} correct`)}</div>
         <p>Sample: ${esc(plural(acc.runs, "live run"))} on generated alerts in the last 24 hours${acc.runs < 20 ? ", too few to generalize from" : ""}. Demo runs don't count.</p>`
      : `<div class="db-accuracy-label">Live verdict accuracy</div>
         <div class="db-accuracy-value">No live sample</div>
         <p>Sample: 0 live runs on generated alerts in the last 24 hours. Demo runs are scripted, so they don't count.</p>`);
    const o = s.triage.outcomes;
    const parts = (counts) => PARTS.filter(([k]) => counts[k]).map(([k, name, color]) => ({ key: k, name, color, n: counts[k] }));
    const groups = [
      { id: "live", title: "Live investigations", parts: parts(o.live), empty: "No live investigations in the last 24 hours." },
      { id: "demo", title: "Demo investigations", tag: "Scripted, not a result", parts: parts(o.demo), scripted: true },
      { id: "open", title: "Not finished", parts: [
        ...(o.in_progress ? [{ key: "in_progress", name: "in progress", color: "var(--series-5)", n: o.in_progress }] : []),
        ...(o.awaiting ? [{ key: "awaiting", name: "awaiting triage, no run yet", color: "var(--series-muted)", n: o.awaiting }] : [])] },
    ];
    const total = (g) => g.parts.reduce((n, p) => n + p.n, 0);
    const scale = Math.max(1, ...groups.map(total));
    groups.forEach((g) => g.parts.forEach((p) => {
      tips[`part:${g.id}:${p.key}`] = { title: g.title, rows: [[`${p.name}, ${Math.round(p.n / total(g) * 100)}% of this row`, num(p.n), p.color]] };
    }));
    put("db-outcomes-table", table([["Outcome"], ["Live", "n"], ["Demo (scripted)", "n"]],
      [...PARTS.map(([k, name]) => [capital(name), o.live[k], o.demo[k]]), ["In progress", o.in_progress, "-"], ["Awaiting triage, no run yet", o.awaiting, "-"]], ""));
    el("db-outcomes-table").closest("details").hidden = !groups.some(total);
    if (!groups.some(total)) {
      put("db-outcomes", emptyNote("Nothing to break down yet.", "Generate an alert on the agent page and start a run."));
      return;
    }
    put("db-outcomes", groups.filter((g) => total(g) || g.empty).map((g) => {
      if (!total(g)) return `<div class="db-outcome"><div class="db-outcome-head"><b>${esc(g.title)}</b><span class="db-outcome-total">0</span></div><p class="db-empty">${esc(g.empty)}</p></div>`;
      const summary = g.parts.map((p) => `${p.n} ${p.name}`).join(", ");
      return `<div class="db-outcome${g.scripted ? " db-outcome-scripted" : ""}">
        <div class="db-outcome-head"><b>${esc(g.title)}</b>${g.tag ? `<span class="db-tag">${esc(g.tag)}</span>` : ""}<span class="db-outcome-total">${esc(num(total(g)))}</span></div>
        <div class="db-segbar" role="img" aria-label="${esc(`${g.title}${g.tag ? `, ${g.tag}` : ""}: ${summary}`)}" style="width:${total(g) / scale * 100}%">
          ${g.parts.map((p) => `<i data-tip="part:${esc(g.id)}:${esc(p.key)}" style="flex-grow:${p.n};background:${p.color}"></i>`).join("")}
        </div>
        <ul class="db-keys">${g.parts.map((p) => `<li><i style="background:${p.color}"></i><b>${esc(num(p.n))}</b> ${esc(p.name)}</li>`).join("")}</ul>
      </div>`;
    }).join(""));
  }

  // --- investigations table -----------------------------------------------
  let runsData = [], selectedRun = null, sortBy = { key: "started", dir: "desc" }, rowLimit = 15;
  const OUTCOME = {
    true_positive: ["serious", "True positive"], false_positive: ["good", "False positive"], needs_escalation: ["warning", "Needs escalation"],
    failed: ["critical", "Failed"], queued: ["neutral", "Queued"], running: ["neutral", "Running"], no_verdict: ["neutral", "No verdict"],
  };
  const outcomeOf = (r) => r.status === "completed" ? (OUTCOME[r.verdict] ? r.verdict : "no_verdict") : r.status;
  const durationOf = (r) => r.finished_at ? r.finished_at - r.created_at : null;
  const modelOf = (r) => r.models.length ? r.models.join(", ") : r.executed_mode === "demo" ? "Scripted demo" : r.finished_at ? "None" : "Not started";
  const COLUMNS = [
    ["alert", "Alert", "", (r) => r.alert_id],
    ["severity", "Severity", "", (r) => SEVERITY_RANK[r.alert_severity] ?? 9],
    ["outcome", "Outcome", "", (r) => OUTCOME[outcomeOf(r)]?.[1] || r.status],
    ["started", "Started", "", (r) => r.created_at],
    ["by", "By", "", (r) => r.started_by || ""],
    ["model", "Model", "", modelOf],
    ["loops", "Loops", "n", (r) => r.loops],
    ["cost", "Cost", "n", (r) => r.cost_usd],
    ["duration", "Duration", "n", (r) => durationOf(r) ?? Infinity],
  ];

  function filteredRuns() {
    const q = el("db-f-q").value.trim().toLowerCase(), severity = el("db-f-severity").value, outcome = el("db-f-outcome").value, mode = el("db-f-mode").value;
    const rows = runsData.filter((r) => {
      if (severity && r.alert_severity !== severity) return false;
      if (mode && r.executed_mode !== mode) return false;
      if (outcome === "active" ? r.finished_at || r.status === "failed" : outcome && outcomeOf(r) !== outcome) return false;
      return !q || [r.alert_id, r.alert_title, r.started_by, r.id, modelOf(r)].some((v) => v && String(v).toLowerCase().includes(q));
    });
    const column = COLUMNS.find((c) => c[0] === sortBy.key), sign = sortBy.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = column[3](a), y = column[3](b);
      return sign * (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) || b.created_at - a.created_at;
    });
  }

  function runRow(r) {
    const [level, text] = OUTCOME[outcomeOf(r)] || ["neutral", capital(r.status)];
    const wait = r.human_wait_seconds > 0.5 ? `<small title="Time waiting for a person to approve">${esc(secs(r.human_wait_seconds))} on approval</small>` : "";
    const open = r.id === selectedRun;
    return `<tr data-run="${esc(r.id)}" data-alert="${esc(r.alert_id)}"${open ? ' aria-current="true" class="db-selected"' : ""}>
      <td class="db-col-alert"><button type="button" class="db-link" data-fk="run-${esc(r.id)}" aria-label="${esc(`Open trace for ${r.alert_id}, run ${r.id}`)}">${esc(r.alert_id)}</button><small>${esc(r.alert_title || "Unknown alert")}</small></td>
      <td>${severityTag(r.alert_severity)}</td>
      <td>${state(level, text)}${r.executed_mode === "demo" && r.status === "completed" ? '<small>Scripted</small>' : ""}</td>
      <td class="db-nowrap">${esc(new Date(r.created_at * 1000).toLocaleTimeString())}</td>
      <td>${esc(r.started_by || "-")}</td>
      <td>${esc(modelOf(r))}${r.architecture === "multi" ? "<small>Multi-agent</small>" : ""}</td>
      <td class="n">${esc(r.loops)}${r.attempts > 1 ? `<small>over ${esc(r.attempts)} attempts</small>` : ""}</td>
      <td class="n">${esc(usd(r.cost_usd))}</td>
      <td class="n">${r.finished_at ? esc(secs(durationOf(r))) : esc(r.status === "failed" ? "-" : "Running")}${wait}</td>
      <td class="db-col-go" aria-hidden="true">${open ? "Open" : "Trace"}<svg viewBox="0 0 16 16"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg></td>
    </tr>`;
  }

  function renderRuns() {
    const rows = filteredRuns(), shown = rows.slice(0, rowLimit);
    const filtering = ["db-f-q", "db-f-severity", "db-f-outcome", "db-f-mode"].some((id) => el(id).value);
    el("db-run-count").textContent = runsData.length ? `${rows.length} of ${runsData.length}${runsData.length >= 50 ? " newest" : ""}` : "";
    if (!runsData.length) {
      put("db-runs", emptyNote("No investigations yet.", "Pick an alert on the agent page and run it. Each run appears here with its verdict, cost and trace."));
      put("db-runs-foot", "");
      return;
    }
    if (!rows.length) {
      put("db-runs", `<div class="db-empty-box"><b>No investigations match these filters.</b><button type="button" class="db-btn" data-action="clear-filters" data-fk="clear">Clear filters</button></div>`);
      put("db-runs-foot", "");
      return;
    }
    const heads = COLUMNS.map(([key, name, cls]) => {
      const active = sortBy.key === key;
      const sort = active ? (sortBy.dir === "asc" ? "ascending" : "descending") : "none";
      return `<th scope="col" class="${cls}${key === "alert" ? " db-col-alert" : ""}" aria-sort="${sort}"><button type="button" class="db-sort" data-sort="${key}" data-fk="sort-${key}">${esc(name)}<span aria-hidden="true">${active ? (sortBy.dir === "asc" ? "▲" : "▼") : ""}</span></button></th>`;
    }).join("");
    put("db-runs", `<table class="db-table db-runs-table"><thead><tr>${heads}<th scope="col" class="db-col-go"><span class="db-sr">Open trace</span></th></tr></thead><tbody>${shown.map(runRow).join("")}</tbody></table>`);
    const parts = [];
    if (rows.length > shown.length) parts.push(`<button type="button" class="db-btn" data-action="more" data-fk="more">Show ${Math.min(15, rows.length - shown.length)} more</button>`);
    if (filtering) parts.push('<button type="button" class="db-btn" data-action="clear-filters" data-fk="clear">Clear filters</button>');
    if (rows.some((r) => r.executed_mode === "demo")) parts.push('<p class="db-foot">Scripted rows are demo runs: their verdicts, calls and timings are not results.</p>');
    put("db-runs-foot", parts.join(""));
  }

  function clearFilters() {
    el("db-f-q").value = ""; ["db-f-severity", "db-f-outcome", "db-f-mode"].forEach((id) => { el(id).value = ""; });
    rowLimit = 15;
    renderRuns();
  }

  // --- secondary panels ---------------------------------------------------
  function panel(name, gist, html) {
    put(`db-g-${name}`, esc(gist));
    put(`db-p-${name}`, html);
  }

  function renderPanels(s) {
    const LAT = { "queue.wait": "Waiting for a worker", "agent.attempt": "Whole attempt", "llm.call": "Model call", "approval.wait": "Waiting for a human" };
    panel("latency", s.latency["agent.attempt"].count ? `Median attempt ${secs(s.latency["agent.attempt"].p50)}` : "No runs yet",
      table([["Stage"], ["Count", "n"], ["Median", "n"], ["95th", "n"]], Object.entries(LAT).map(([k, label]) => [label, s.latency[k].count, secs(s.latency[k].p50), secs(s.latency[k].p95)]), ""));

    const toolErrors = s.tools.reduce((n, t) => n + (t.errors || 0), 0);
    panel("tools", s.tools.length ? `${plural(s.tools.length, "tool")}, ${plural(toolErrors, "error")}` : "No calls yet",
      table([["Tool"], ["Calls", "n"], ["Errors", "n"], ["Median", "n"], ["95th", "n"]], s.tools.map((t) => [t.tool, t.calls, t.errors, secs(t.p50), secs(t.p95)]),
        "No tool calls yet. Start a run on the agent page."));

    panel("models", s.models.length ? plural(s.models.length, "model") : "No live calls",
      table([["Model"], ["Runs", "n"], ["Calls", "n"], ["Loops per run", "n"], ["Most in a run", "n"], ["Input tokens", "n"], ["Output tokens", "n"], ["Est. cost", "n"]],
        s.models.map((m) => [m.model, m.runs, m.calls, m.avg_loops.toFixed(1), `${m.max_loops} of ${s.max_steps}`, num(m.input_tokens), num(m.output_tokens), usd(m.cost_usd)]),
        "No live model calls in the last 24 hours. Demo runs are scripted and don't use a model."));

    panel("agents", s.agents.length ? plural(s.agents.length, "agent") : "No live multi-agent calls",
      table([["Agent"], ["Runs", "n"], ["Model calls", "n"], ["Tool calls", "n"], ["Input tokens", "n"], ["Est. cost", "n"]],
        s.agents.map((a) => [a.agent, a.runs, a.calls, a.tool_calls, num(a.input_tokens), usd(a.cost_usd)]),
        "No live multi-agent model calls yet. Demo runs are scripted and don't use a model."));

    const demoCompare = s.architectures.some((a) => a.mode === "demo" || a.mode === "auto");
    panel("compare", s.architectures.length ? (s.architectures.every((a) => a.mode === "demo") ? "Demo only, not results" : plural(s.architectures.reduce((n, a) => n + a.runs, 0), "completed run")) : "No completed runs",
      table([["Architecture"], ["Mode"], ["Runs", "n"], ["Model calls", "n"], ["Tool calls", "n"], ["Time", "n"], ["Cost", "n"]],
        s.architectures.map((a) => [a.architecture, a.mode === "demo" ? "demo (scripted)" : a.mode, a.runs, a.avg_model_calls.toFixed(1), a.avg_tool_calls.toFixed(1), secs(a.avg_seconds), usd(a.avg_cost_usd)]),
        "No completed runs yet. Averages per completed run appear here, excluding approval waits.")
      + (demoCompare ? '<p class="db-foot">Averages per completed run, excluding approval waits. Demo rows are scripted: compare live rows only.</p>' : ""));

    const m = s.model;
    panel("provider", m.turns ? plural(m.turns, "response") : "No live responses",
      table([["Measure"], ["Value", "n"]], [
        ["Model responses", num(m.turns)], ["Input / output tokens", `${num(m.input_tokens)} / ${num(m.output_tokens)}`], ["Cached input tokens", num(m.cache_read_tokens)], ["Declined", num(m.refusals)],
        ...m.http.map((c) => [`${c.labels.provider} HTTP ${c.labels.status}`, num(c.value)]),
        ...m.errors.map((c) => [`${c.labels.provider} ${c.labels.kind}`, num(c.value)]),
      ], ""));

    const refused = Object.entries(s.safety.policy).filter(([d]) => d !== "allow" && d !== "needs_approval").reduce((n, [, v]) => n + v, 0);
    panel("safety", `${plural(s.safety.injection_flags, "injection flag")}, ${plural(refused, "call")} refused by policy`,
      table([["Measure"], ["Count", "n"]], [
        ["Prompt injection flags", num(s.safety.injection_flags)],
        ...Object.entries(s.safety.policy).map(([d, n]) => [`Policy: ${words(d)}`, num(n)]),
        ...s.safety.approvals.map((c) => [`${c.labels.tool}: ${c.labels.outcome}`, num(c.value)]),
        ...s.safety.auth.map((c) => [`Access: ${words(c.labels.kind)}`, num(c.value)]),
      ], ""));

    const r = s.reliability, open = s.circuits.filter((c) => c.state !== "closed").length;
    panel("reliability", open ? `${plural(open, "circuit")} not closed` : `${plural(r.retries, "retry").replace("retrys", "retries")}, circuits closed`,
      table([["Measure"], ["Value", "n"]], [
        ["Jobs waiting / running", `${num(s.queue.queued)} / ${num(s.queue.leased)}`], ["95th percentile queue wait", secs(s.latency["queue.wait"].p95)],
        ["Retries", num(r.retries)], ["Resumed from a checkpoint", num(r.resumed)], ["Repeat actions prevented", num(r.idempotent_replays)],
        ["Paused for an outage", num(r.deferred)], ["Stopped after losing a job", num(r.leases_lost)],
        ...s.circuits.map((c) => [`Circuit ${c.name}`, c.state.replace("_", "-")]),
      ], ""));

    const acc = s.alert_queue.accuracy;
    panel("queue", `${num(s.alert_queue.waiting)} waiting`,
      table([["Measure"], ["Value", "n"]], [
        ["Waiting for triage", num(s.alert_queue.waiting)], ["Generated", num(s.alert_queue.generated)], ["Repeats merged", num(s.alert_queue.deduplicated)],
        ["Correct verdicts, live runs on generated alerts", acc.runs ? `${acc.correct} of ${acc.runs}` : "No live runs yet"],
        ["Cost per completed run", usd(s.cost_per_completed_run)],
      ], ""));
  }

  // --- trace --------------------------------------------------------------
  let traceRun = null, traceToken = 0;

  function spanInfo(s) {
    const n = s.name;
    if (n === "llm.call") return { kind: "Model", color: "var(--series-1)", label: "Model call" };
    if (n.startsWith("tool.")) return { kind: "Tool", color: "var(--series-2)", label: n.slice(5) };
    if (n === "approval.wait") return { kind: "Human", color: "var(--series-3)", label: `Approval${s.attrs.tool ? `: ${s.attrs.tool}` : ""}` };
    const color = "var(--series-muted)";
    if (n === "queue.wait") return { kind: "Platform", color, label: "Waiting for a worker" };
    if (n === "api.enqueue") return { kind: "Platform", color, label: "Added to the queue" };
    if (n === "agent.attempt") return { kind: "Platform", color, label: `Attempt ${s.attrs.attempt ?? ""}`.trim() };
    if (n.startsWith("agent.")) return { kind: "Platform", color, label: "Whole assignment" };
    return { kind: "Platform", color, label: n };
  }
  const KINDS = [["Platform", "var(--series-muted)"], ["Model", "var(--series-1)"], ["Tool", "var(--series-2)"], ["Human", "var(--series-3)"]];
  const specialistName = (a) => `${capital(a)} specialist`;

  // In a multi-agent run, each agent gets its own lane, so it's clear who did what and what ran in parallel.
  function traceLanes(spans) {
    const multi = spans.some((s) => s.attrs.agent || (s.name === "agent.attempt" && s.attrs.architecture === "multi"));
    if (!multi) return [{ id: "all", title: null, spans }];
    const lanes = new Map([["run", { id: "run", title: "Run", note: "Queue, attempts and approvals", spans: [] }]]);
    for (const s of spans) {
      const worker = s.name === "llm.call" || s.name.startsWith("tool.");
      const id = s.attrs.agent || (worker ? "coordinator" : "run");
      if (!lanes.has(id)) lanes.set(id, { id, title: id === "coordinator" ? "Coordinator" : specialistName(id), spans: [] });
      lanes.get(id).spans.push(s);
    }
    const ordered = [...lanes.values()].filter((l) => l.spans.length);
    const rest = ordered.filter((l) => l.id !== "run" && l.id !== "coordinator");
    return [lanes.get("run"), lanes.get("coordinator"), ...rest].filter((l) => l && l.spans.length);
  }

  function axisStep(total) {
    const options = [];
    for (let p = 1e-3; p <= 1e5; p *= 10) options.push(p, 2 * p, 5 * p);
    return options.find((v) => total / v <= 5);
  }

  function renderTrace(id, alert, spans) {
    const run = runsData.find((r) => r.id === id);
    const alertId = alert || (run && run.alert_id);
    el("db-trace-title").textContent = alertId ? `Trace: ${alertId}, run ${id}` : `Trace: run ${id}`;
    if (run) {
      const [, outcome] = OUTCOME[outcomeOf(run)] || [null, capital(run.status)];
      el("db-trace-meta").textContent = [run.alert_title, outcome, run.executed_mode === "demo" ? "scripted demo, so timings are not results" : run.executed_mode, run.architecture === "multi" ? "multi-agent" : "single agent"].filter(Boolean).join(" · ");
    } else {
      el("db-trace-meta").textContent = "";
    }
    if (!spans.length) {
      put("db-trace", emptyNote("This run has no trace yet.", "It may still be queued, or it ran before tracing was added."));
      put("db-trace-table", '<p class="db-empty">No spans.</p>');
      return;
    }
    const t0 = Math.min(...spans.map((s) => s.start_ts));
    const total = Math.max(...spans.map((s) => s.end_ts)) - t0 || 1;
    const step = axisStep(total), stepShare = step / total * 100;
    const errors = spans.filter((s) => s.status === "error").length;
    const human = spans.filter((s) => s.name === "approval.wait").reduce((n, s) => n + s.end_ts - s.start_ts, 0);
    const lanes = traceLanes(spans);
    const ticks = [];
    for (let t = 0; t <= total; t += step) ticks.push(t);

    const facts = [`Total ${secs(total)}`, plural(spans.length, "span")];
    if (human) facts.push(`${secs(human)} waiting for a person`);
    if (lanes.length > 1) facts.push(plural(lanes.length - 1, "agent"));

    tips = Object.fromEntries(Object.entries(tips).filter(([k]) => !k.startsWith("span:")));
    let first = true;
    const row = (s) => {
      const info = spanInfo(s), dur = s.end_ts - s.start_ts, offset = s.start_ts - t0;
      tips[`span:${s.span_id}`] = { title: `${secs(dur)}, ${info.kind.toLowerCase()}`, rows: [
        ["span", s.name], ["starts after", secs(offset)], ...(s.status === "error" ? [["status", "error"]] : []),
        ...Object.entries(s.attrs).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => [words(k), String(v)])] };
      const tab = first ? 0 : -1;
      first = false;
      return `<div class="db-wf-row" role="listitem" data-rove data-tip="span:${esc(s.span_id)}" data-fk="span-${esc(s.span_id)}" tabindex="${tab}"
          aria-label="${esc(`${info.label}, ${info.kind}, ${secs(dur)}, starts after ${secs(offset)}${s.status === "error" ? ", failed" : ""}`)}">
        <div class="db-wf-name">${s.status === "error" ? `${icon("critical")}<span class="db-sr">Failed: </span>` : ""}<span>${esc(info.label)}</span></div>
        <div class="db-wf-track" style="background-size:${stepShare}% 100%"><i style="left:${offset / total * 100}%;width:${dur / total * 100}%;background:${info.color}"></i></div>
        <div class="db-wf-d">${esc(secs(dur))}</div>
      </div>`;
    };
    put("db-trace", `
      <div class="db-trace-facts">${facts.map((f) => `<span>${esc(f)}</span>`).join("")}${errors ? `<span>${state("critical", plural(errors, "failed span"))}</span>` : ""}</div>
      <div class="db-legend">${KINDS.map(([n, c]) => `<span><i style="background:${c}"></i>${esc(n)}</span>`).join("")}</div>
      <div class="db-wf" role="group" aria-label="Spans in time order. Use the up and down arrow keys to move between them.">
        <div class="db-wf-row db-wf-axis" aria-hidden="true"><div></div><div class="db-wf-ticks">${ticks.map((t) => `<span${t / total > 0.92 ? ' class="db-tick-end"' : ""} style="left:${t / total * 100}%">${esc(t === 0 ? "0" : secs(t))}</span>`).join("")}</div><div></div></div>
        ${lanes.map((l) => `<div class="db-wf-lane${l.title ? " db-wf-lane-named" : ""}">
          ${l.title ? `<div class="db-wf-lane-title"><b>${esc(l.title)}</b>${l.note ? `<span>${esc(l.note)}</span>` : ""}</div>` : ""}
          <div role="list" aria-label="${esc(l.title || "Spans")}">${l.spans.map(row).join("")}</div>
        </div>`).join("")}
      </div>`);
    put("db-trace-table", table([["Agent"], ["Span"], ["Kind"], ["Starts after", "n"], ["Duration", "n"], ["Status"]],
      lanes.flatMap((l) => l.spans.map((s) => [l.title || "Single agent", spanInfo(s).label, spanInfo(s).kind, secs(s.start_ts - t0), secs(s.end_ts - s.start_ts), s.status])), ""));
  }

  async function openTrace(id, alert, quiet) {
    mount();
    const changed = !traceRun || traceRun.id !== id;
    traceRun = { id, alert: alert || (traceRun && traceRun.id === id ? traceRun.alert : null) };
    if (selectedRun !== id) { selectedRun = id; renderRuns(); }
    const token = ++traceToken;
    const card = el("db-trace-card");
    card.hidden = false;
    if (changed) { put("db-trace", '<p class="db-empty">Loading trace.</p>'); put("db-trace-table", ""); }
    if (!quiet) {
      card.scrollIntoView({ block: "start" });
      el("db-trace-title").focus({ preventScroll: true });
    }
    try {
      const res = await api(`/api/runs/${encodeURIComponent(id)}/trace`);
      if (token !== traceToken) return;  // the analyst has opened another trace since this was requested
      if (!res.ok) {
        el("db-trace-title").textContent = `Trace: run ${id}`;
        el("db-trace-meta").textContent = "";
        put("db-trace", emptyNote(res.status === 404 ? "This run doesn't exist." : "The trace couldn't be loaded.", res.status === 404 ? "It may have been removed. Choose another investigation above." : "Try again in a moment."));
        put("db-trace-table", "");
        return;
      }
      const spans = await res.json();
      if (token !== traceToken) return;
      renderTrace(id, traceRun.alert, spans);
    } catch (err) {
      if (changed && token === traceToken) put("db-trace", emptyNote("The trace couldn't be loaded.", "Check the connection. It will try again on the next refresh."));
    }
  }

  function closeTrace() {
    const id = selectedRun;
    traceToken++;
    traceRun = null; selectedRun = null;
    el("db-trace-card").hidden = true;
    hideTip();
    renderRuns();
    const button = el("db-runs").querySelector(`[data-fk="run-${CSS.escape(id || "")}"]`);
    if (button) button.focus({ preventScroll: true });
  }

  // --- loading ------------------------------------------------------------
  let loading = false, loadedAt = null;

  async function refresh() {
    if (loading) return;  // a slow response mustn't stack up behind the timer
    loading = true;
    try {
      const res = await api("/api/obs/summary");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      render(await res.json());
      loadedAt = new Date();
      el("db-status").textContent = `Updated ${loadedAt.toLocaleTimeString()}. Refreshes every 5 seconds.`;
      el("db-status").classList.remove("db-status-stale");
    } catch (err) {
      const status = el("db-status");
      if (status) {
        status.textContent = loadedAt ? `Couldn't refresh. Showing data from ${loadedAt.toLocaleTimeString()}.` : "Couldn't load the dashboard data. Trying again.";
        status.classList.add("db-status-stale");
      }
      console.error("dashboard refresh failed", err);
    } finally {
      loading = false;
    }
    if (traceRun) openTrace(traceRun.id, traceRun.alert, true);
  }

  function render(s) {
    const finishedDemo = Object.entries(s.triage.outcomes.demo).reduce((n, [, v]) => n + v, 0);
    const finishedLive = Object.entries(s.triage.outcomes.live).reduce((n, [, v]) => n + v, 0);
    const banner = el("db-demo-banner");
    banner.hidden = !finishedDemo;
    if (finishedDemo) banner.textContent = finishedLive
      ? `${finishedDemo} of ${finishedDemo + finishedLive} finished runs in the last 24 hours are scripted demo runs. They show the workflow, not model results.`
      : `All ${finishedDemo} finished runs in the last 24 hours are scripted demo runs. They show the workflow, not model results.`;
    renderAttention(s);
    renderKpis(s);
    renderActivity(s);
    renderOutcomes(s);
    runsData = s.recent_runs;
    renderRuns();
    renderPanels(s);
  }

  // --- wiring: one set of listeners on the fixed frame, so re-rendering regions can't drop them ------
  function rove(ev) {
    const current = ev.target.closest("[data-rove]");
    if (!current) return;
    const axis = current.classList.contains("db-hour") ? ["ArrowLeft", "ArrowRight"] : ["ArrowUp", "ArrowDown"];
    if (![...axis, "Home", "End"].includes(ev.key)) return;
    const scope = current.closest(".db-plot, .db-wf");
    const items = [...scope.querySelectorAll("[data-rove]")];
    const at = items.indexOf(current);
    const next = ev.key === axis[0] ? items[at - 1] : ev.key === axis[1] ? items[at + 1] : ev.key === "Home" ? items[0] : items[items.length - 1];
    if (!next) return;
    ev.preventDefault();
    current.tabIndex = -1; next.tabIndex = 0;
    next.focus();
  }

  function wire(root) {
    root.addEventListener("pointermove", (ev) => {
      const hit = ev.target.closest && ev.target.closest("[data-tip]");
      if (hit) showTip(hit.dataset.tip, ev.clientX, ev.clientY); else hideTip();
    });
    root.addEventListener("pointerleave", hideTip);
    root.addEventListener("focusin", (ev) => {
      const hit = ev.target.closest("[data-tip]");
      if (!hit || !hit.matches(":focus-visible")) return;
      const box = hit.getBoundingClientRect();
      showTip(hit.dataset.tip, box.left + Math.min(box.width, 120) / 2, box.bottom);
    });
    root.addEventListener("focusout", hideTip);
    root.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") hideTip();
      rove(ev);
    });
    root.addEventListener("click", (ev) => {
      const sort = ev.target.closest("[data-sort]");
      if (sort) {
        const key = sort.dataset.sort;
        sortBy = sortBy.key === key ? { key, dir: sortBy.dir === "asc" ? "desc" : "asc" } : { key, dir: ["started", "cost", "duration", "loops"].includes(key) ? "desc" : "asc" };
        renderRuns();
        return;
      }
      const action = ev.target.closest("[data-action]");
      if (action) {
        if (action.dataset.action === "clear-filters") clearFilters();
        if (action.dataset.action === "more") { rowLimit += 15; renderRuns(); }
        return;
      }
      const row = ev.target.closest("tr[data-run]");
      if (row) openTrace(row.dataset.run, row.dataset.alert);
    });
    el("db-filters").addEventListener("submit", (ev) => ev.preventDefault());
    el("db-filters").addEventListener("input", () => { rowLimit = 15; renderRuns(); });
    el("db-trace-close").addEventListener("click", closeTrace);
  }

  function mount() {
    const root = $("#obs");
    if (!root || el("db-kpis")) return;
    root.innerHTML = MARKUP;
    rendered.clear();
    wire(root);
  }

  return { mount, refresh, openTrace, hideTip };
})();

function showDashboard(on) {
  const obs = $("#obs");
  if (!obs) return;
  if (on) obsDashboard.mount();
  const app = $("#app"), toggle = $("#view-toggle");
  if (app) app.hidden = on;
  obs.hidden = !on;
  if (toggle) toggle.textContent = on ? "Agent" : "Dashboard";
  clearInterval(obsTimer);
  obsTimer = null;
  if (on) {
    obsDashboard.refresh();
    obsTimer = setInterval(() => {
      if ($("#obs").hidden) { clearInterval(obsTimer); obsTimer = null; obsDashboard.hideTip(); return; }
      if (!document.hidden) obsDashboard.refresh();
    }, 5000);
  } else {
    obsDashboard.hideTip();
  }
}

function loadTrace(id, alert, quiet) {
  return obsDashboard.openTrace(id, alert, quiet);
}

if ($("#view-toggle")) $("#view-toggle").onclick = () => {
  const on = $("#obs").hidden;
  location.hash = on ? "dashboard" : "";
  if ($("#users")) $("#users").hidden = true;
  if ($("#users-toggle")) $("#users-toggle").textContent = "Users";
  showDashboard(on);
};
