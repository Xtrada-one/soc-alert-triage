"use strict";
const SEV = ["Critical", "High", "Medium", "Low"];
const state = { uploadId: null, cfg: { statuses: [], scenarios: [], llm_enabled: false } };
const $ = (s) => document.querySelector(s);

// Semua teks dari log ditampilkan lewat textContent (anti-XSS); tidak ada innerHTML.
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) el.append(kid instanceof Node ? kid : String(kid ?? ""));
  return el;
}
const svgEl = (tag, attrs = {}, text) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text != null) el.textContent = text;
  return el;
};
async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const jsonOpts = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const q = () => (state.uploadId ? `?upload_id=${state.uploadId}` : "");
const fmtTime = (s) => (s || "").replace("T", " ");
const badge = (sev) => h("span", { class: `badge ${sev}` }, sev);

function notice(msg, isError = false) {
  const n = $("#notice");
  n.textContent = msg; n.hidden = !msg;
  n.className = "notice" + (isError ? " error" : "");
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { notice(e.message, true); } };

// ---------- ringkasan ----------
function renderStrip(s) {
  const box = $("#strip"); box.replaceChildren();
  if (!s.upload) { box.append(h("p", { class: "empty" }, "Belum ada hasil analisis. Unggah file log atau jalankan skenario uji di atas.")); return; }
  const u = s.upload;
  box.append(h("div", { class: "strip-meta" },
    h("span", {}, h("b", {}, s.total_incidents), "insiden (per IP)"),
    h("span", {}, h("b", {}, s.total_alerts), "alert"),
    h("span", {}, `${u.events} event dari ${u.total_lines} baris, ${u.invalid_lines} baris tidak valid`),
    h("span", {}, `Sumber: ${u.filename}`)));
  if (!s.total_alerts) { box.append(h("p", { class: "empty" }, "Tidak ada alert pada log ini.")); return; }
  const strip = h("div", { class: "strip", role: "img", "aria-label": "Proporsi alert per severity" });
  for (const sev of SEV) {
    const n = s.severity_counts[sev];
    if (n) strip.append(h("div", { class: `seg ${sev}`, style: `flex-grow:${n}` }, `${sev} ${n}`));
  }
  box.append(strip);
}

function renderTimeline(t) {
  const box = $("#timeline"); box.replaceChildren();
  if (!t.points.length) { box.append(h("p", { class: "empty" }, "Belum ada data.")); return; }
  const W = 560, H = 170, L = 28, B = 22, T = 8, n = t.points.length;
  const max = Math.max(1, ...t.points.map((p) => SEV.reduce((a, s) => a + p[s], 0)));
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": `Jumlah alert per ${t.bucket}` });
  const bw = Math.max(2, Math.min(28, (W - L) / n - 3));
  const colors = { Critical: "#a4161a", High: "#c2410c", Medium: "#8a6a00", Low: "#46708a" };
  svg.append(svgEl("line", { x1: L, x2: W, y1: H - B, y2: H - B, stroke: "#d3dae1" }));
  svg.append(svgEl("text", { x: 0, y: T + 8 }, String(max)));
  svg.append(svgEl("text", { x: 0, y: H - B }, "0"));
  t.points.forEach((p, i) => {
    const x = L + (i + 0.5) * ((W - L) / n) - bw / 2;
    let y = H - B;
    for (const sev of [...SEV].reverse()) {
      const hgt = (p[sev] / max) * (H - B - T);
      if (!p[sev]) continue;
      y -= hgt;
      svg.append(svgEl("rect", { x, y, width: bw, height: hgt, fill: colors[sev] }));
    }
  });
  svg.append(svgEl("text", { x: L, y: H - 5 }, fmtTime(t.points[0].t)));
  svg.append(svgEl("text", { x: W, y: H - 5, "text-anchor": "end" }, fmtTime(t.points[n - 1].t)));
  box.append(svg, h("div", { class: "legend" }, ...SEV.map((s) => h("span", {}, h("i", { style: `background:${colors[s]}` }), s)),
    h("span", {}, `per ${t.bucket}`)));
}

function renderTop(list) {
  const box = $("#topips"); box.replaceChildren();
  if (!list.length) { box.append(h("p", { class: "empty" }, "Belum ada data.")); return; }
  const colors = { Critical: "var(--critical)", High: "var(--high)", Medium: "var(--medium)", Low: "var(--low)" };
  const max = Math.max(...list.map((i) => i.score));
  for (const i of list)
    box.append(h("div", { class: "toprow" }, h("span", { class: "ip" }, i.src_ip),
      h("div", {}, h("div", { class: "bar", style: `width:${(i.score / max) * 100}%;background:${colors[i.severity]}` })),
      h("span", { class: "score" }, i.score)));
}

// ---------- insiden ----------
function alertBox(a) {
  return h("div", { class: "alertbox" },
    h("h4", {}, `${a.rule_id} ${a.rule_name} `, badge(a.severity), ` ${a.count} kejadian, skor ${a.score}`),
    h("div", {}, a.detail),
    a.mitre.length ? h("div", {}, ...a.mitre.map((m) => h("span", { class: "chip" }, m))) : "",
    h("pre", {}, a.evidence.join("\n")));
}

async function explain(ip, target) {
  target.textContent = "Meminta penjelasan dari model lokal...";
  try {
    const r = await api(`/api/explain${q()}`, jsonOpts("POST", { ip }));
    target.textContent = r.text || "LLM tidak aktif.";
  } catch (e) { target.textContent = e.message; }
}

function renderIncidents(list) {
  const box = $("#tab-incidents"); box.replaceChildren();
  if (!list.length) { box.append(h("p", { class: "empty" }, "Tidak ada insiden.")); return; }
  const tbody = h("tbody");
  for (const inc of list) {
    const detail = h("tr", { class: "detail", hidden: true }, h("td", { colspan: 6 }));
    const ex = h("div", { class: "explain", hidden: true });
    const cell = detail.firstChild;
    cell.append(...inc.alerts.map(alertBox),
      h("h4", {}, "Rekomendasi respons"), h("ol", { class: "recs" }, ...inc.recommendations.map((r) => h("li", {}, r))));
    if (state.cfg.llm_enabled)
      cell.append(h("button", { type: "button", onclick: () => { ex.hidden = false; explain(inc.src_ip, ex); } }, "Jelaskan dengan LLM lokal"), ex);
    const row = h("tr", { class: "row", tabindex: 0, "aria-expanded": "false" },
      h("td", {}, badge(inc.severity)),
      h("td", { class: "ip" }, inc.src_ip),
      h("td", { class: "score" }, inc.score),
      h("td", {}, inc.rules.map((r) => h("span", { class: "chip", title: r.name }, r.id)), inc.correlated ? h("span", { class: "chip" }, "terkorelasi") : ""),
      h("td", { class: "col-hide" }, `${fmtTime(inc.first_seen)} sampai ${fmtTime(inc.last_seen)}`),
      h("td", {}, inc.status));
    const toggle = () => { detail.hidden = !detail.hidden; row.setAttribute("aria-expanded", String(!detail.hidden)); };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    tbody.append(row, detail);
  }
  box.append(h("table", {}, h("thead", {}, h("tr", {}, ...["Severity", "IP sumber", "Skor", "Rule terpicu", "Periode", "Status"].map((t) => h("th", {}, t)))), tbody),
    h("p", { class: "hint" }, "Klik baris untuk melihat bukti dan rekomendasi."));
}

// ---------- alert ----------
function statusSelect(a) {
  const sel = h("select", { "aria-label": `Status alert ${a.rule_id} ${a.src_ip}` },
    ...state.cfg.statuses.map((s) => h("option", { value: s, selected: s === a.status }, s)));
  sel.addEventListener("change", guard(async () => {
    await api(`/api/alerts/${a.id}`, jsonOpts("PATCH", { status: sel.value }));
    await loadIncidents();
  }));
  return sel;
}
async function loadAlerts() {
  const p = new URLSearchParams();
  if (state.uploadId) p.set("upload_id", state.uploadId);
  for (const [k, id] of [["severity", "#fSeverity"], ["status", "#fStatus"], ["q", "#fQuery"]]) if ($(id).value) p.set(k, $(id).value);
  const list = await api(`/api/alerts?${p}`);
  const box = $("#alertsTable"); box.replaceChildren();
  if (!list.length) { box.append(h("p", { class: "empty" }, "Tidak ada alert yang cocok dengan filter.")); return; }
  box.append(h("table", {},
    h("thead", {}, h("tr", {}, ...["Severity", "IP sumber", "Rule", "Kejadian", "Skor", "Status"].map((t) => h("th", {}, t)))),
    h("tbody", {}, ...list.map((a) => h("tr", {},
      h("td", {}, badge(a.severity)), h("td", { class: "ip" }, a.src_ip),
      h("td", {}, `${a.rule_id} ${a.rule_name}`, h("div", { class: "hint", style: "margin:0" }, a.detail)),
      h("td", {}, a.count), h("td", { class: "score" }, a.score), h("td", {}, statusSelect(a)))))));
}

// ---------- whitelist ----------
async function loadWhitelist() {
  const list = await api("/api/whitelist");
  const box = $("#wlTable"); box.replaceChildren();
  if (!list.length) { box.append(h("p", { class: "empty" }, "Whitelist kosong.")); return; }
  box.append(h("table", {}, h("thead", {}, h("tr", {}, ...["IP", "Catatan", "Ditambahkan", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, ...list.map((w) => h("tr", {}, h("td", { class: "ip" }, w.ip), h("td", {}, w.note), h("td", {}, fmtTime(w.added_at)),
      h("td", {}, h("button", { type: "button", onclick: guard(async () => { await api(`/api/whitelist/${encodeURIComponent(w.ip)}`, { method: "DELETE" }); await loadWhitelist(); }) }, "Hapus")))))));
}

// ---------- pemuatan data ----------
async function loadIncidents() { renderIncidents(await api(`/api/incidents${q()}`)); }
async function refresh() {
  const s = await api(`/api/summary${q()}`);
  renderStrip(s); renderTimeline(s.timeline || { points: [] }); renderTop(s.top_ips || []);
  $("#mdLink").href = `/api/report.md${q()}`; $("#htmlLink").href = `/report${q()}`;
  await Promise.all([loadIncidents(), loadAlerts(), loadWhitelist()]);
}
async function loadUploads(selectId) {
  const list = await api("/api/uploads");
  const sel = $("#uploadSelect"); sel.replaceChildren();
  if (!list.length) sel.append(h("option", { value: "" }, "(belum ada)"));
  for (const u of list) sel.append(h("option", { value: u.id }, `#${u.id} ${u.filename.slice(0, 40)}`));
  state.uploadId = list.length ? (selectId ?? list[0].id) : null;
  if (state.uploadId) sel.value = String(state.uploadId);
}
function announce(r) {
  notice(`Selesai: ${r.events} event, ${r.alerts} alert, ${r.incidents} insiden.` +
    (r.invalid_lines ? ` ${r.invalid_lines} baris tidak valid dilewati.` : "") +
    (r.whitelisted_events ? ` ${r.whitelisted_events} event dari IP whitelist diabaikan.` : ""));
}
async function afterAnalysis(r) { await loadUploads(r.upload_id); announce(r); await refresh(); }

// ---------- event ----------
$("#uploadForm").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const fd = new FormData();
  for (const f of $("#file").files) fd.append("file", f);
  fd.append("format", $("#format").value);
  notice("Menganalisis...");
  await afterAnalysis(await api("/api/upload", { method: "POST", body: fd }));
  $("#file").value = "";
}));
$("#runScenario").addEventListener("click", guard(async () => {
  await afterAnalysis(await api("/api/analyze-scenario", jsonOpts("POST", { key: $("#scenarioSelect").value })));
}));
$("#uploadSelect").addEventListener("change", guard(async (e) => { state.uploadId = e.target.value || null; notice(""); await refresh(); }));
$("#delUpload").addEventListener("click", guard(async () => {
  if (!state.uploadId || !confirm("Hapus hasil analisis ini?")) return;
  await api(`/api/uploads/${state.uploadId}`, { method: "DELETE" });
  await loadUploads(); notice("Hasil analisis dihapus."); await refresh();
}));
$("#wlForm").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  await api("/api/whitelist", jsonOpts("POST", { ip: $("#wlIp").value, note: $("#wlNote").value }));
  $("#wlIp").value = ""; $("#wlNote").value = ""; await loadWhitelist();
}));
for (const id of ["#fSeverity", "#fStatus"]) $(id).addEventListener("change", guard(loadAlerts));
$("#fQuery").addEventListener("input", guard(loadAlerts));
for (const t of document.querySelectorAll(".tabs [role=tab]")) t.addEventListener("click", () => {
  for (const o of document.querySelectorAll(".tabs [role=tab]")) {
    const on = o === t;
    o.setAttribute("aria-selected", String(on));
    $(`#tab-${o.dataset.tab}`).hidden = !on;
  }
});

(async function init() {
  try {
    state.cfg = await api("/api/config");
    $("#scenarioSelect").append(...state.cfg.scenarios.map((s) => h("option", { value: s.key }, s.label)));
    $("#fSeverity").append(...state.cfg.severities.map((s) => h("option", { value: s }, s)));
    $("#fStatus").append(...state.cfg.statuses.map((s) => h("option", { value: s }, s)));
    await loadUploads(); await refresh();
  } catch (e) { notice(e.message, true); }
})();
