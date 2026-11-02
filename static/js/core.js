// Shared helpers. Loaded first; everything here is global.
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const pretty = (o) => `<pre>${esc(JSON.stringify(o, null, 2))}</pre>`;
let selected = null, runId = null, stats = {}, me = null;

// Every API call goes through here, so an expired session returns to the login form.
async function api(...args) {
  const res = await fetch(...args);
  if (res.status === 401) { location.reload(); throw new Error("Not logged in"); }
  return res;
}

