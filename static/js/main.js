// Startup and navigation. Loaded last.
function navigate(view, updateHash = true) {
  for (const [name, id] of [["triage", "app"], ["users", "users"]]) $(`#${id}`).hidden = view !== name;
  for (const name of ["triage", "dashboard", "users"]) $(`#nav-${name}`).classList.toggle("on", name === view);
  if (typeof showDashboard === "function") showDashboard(view === "dashboard");
  $("#app").hidden = view !== "triage";  // showDashboard also manages this, so set it last
  $("#obs").hidden = view !== "dashboard";
  if (view === "users") loadUsers();
  if (updateHash) history.replaceState(null, "", view === "triage" ? location.pathname : `#${view}`);
}

// Jump from anywhere to an alert on the investigation screen.
async function openAlert(id) {
  navigate("triage");
  await loadAlerts();
  selectAlert(id);
}

function openFromRow(ev) {
  const row = ev.target.closest("[data-open-alert]");
  if (row && (ev.type === "click" || ev.key === "Enter")) openAlert(row.dataset.openAlert);
}

async function start() {
  $("#obs").addEventListener("click", openFromRow);
  $("#obs").addEventListener("keydown", openFromRow);
  const [hashView, hashValue] = location.hash.slice(1).split("/");
  if (hashView === "invite" && hashValue) { startInvite(hashValue); return; }  // accept it even if someone else is logged in here
  const res = await fetch("/api/me");
  if (!res.ok) { showLoginStep("login-form"); return; }
  me = await res.json();
  $("#me-name").textContent = me.username;
  $("#me-role").textContent = me.role;
  $("#me-avatar").textContent = me.username.slice(0, 2);
  $("#shell").hidden = false;
  const can = (p) => me.permissions.includes(p);  // the server enforces all of these too
  $("#nav-dashboard").hidden = !can("dashboard:view");
  $("#nav-users").hidden = !can("users:manage");
  $("#run-controls").hidden = !can("run");
  $("#flush").hidden = !can("cache:flush");
  $("#generate-box").hidden = !can("alerts:generate");
  $("#nav-triage").onclick = () => navigate("triage");
  $("#nav-dashboard").onclick = () => navigate("dashboard");
  $("#nav-users").onclick = () => navigate("users");
  loadAlerts();
  loadHistory();
  loadQueue();
  loadCache();
  setInterval(() => { if (!$("#app").hidden) { loadQueue(); loadCache(); } }, 2000);
  setInterval(() => { if (!$("#app").hidden) loadAlerts(); }, 5000);  // new alerts appear without a refresh
  // #dashboard opens the dashboard; #dashboard/<run id> also opens that run's trace.
  if (hashView === "dashboard" && can("dashboard:view")) {
    navigate("dashboard", false);
    if (hashValue) loadTrace(hashValue, null);
  } else if (hashView === "users" && can("users:manage")) {
    navigate("users", false);
  } else {
    navigate("triage", false);
  }
}
// An invitation link pasted into a tab already on this app only changes the #fragment, so reload to act on it.
window.addEventListener("hashchange", () => { if (location.hash.startsWith("#invite/")) location.reload(); });
start();
