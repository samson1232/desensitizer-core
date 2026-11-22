/* Desensitizer prompt-flow inspector — no framework, no network beyond same-origin. */
"use strict";

const STAGES = [
  { id: "intake",   n: "01", title: "Intake",   hint: "prompt received" },
  { id: "censor",   n: "02", title: "Censor",   hint: "detect + substitute" },
  { id: "judge",    n: "03", title: "Judge",    hint: "difficulty score" },
  { id: "route",    n: "04", title: "Route",    hint: "local / frontier" },
  { id: "generate", n: "05", title: "Generate", hint: "artifact from model" },
  { id: "restore",  n: "06", title: "Restore",  hint: "reverse placeholders" },
  { id: "verify",   n: "07", title: "Verify",   hint: "completeness + compile" },
  { id: "done",     n: "08", title: "Done",     hint: "outcome class" },
];

const SAMPLES = {
  plant: "Hi, this is Alice Smith (alice.smith@corp.co.uk), calling about the outage at 14 Mill Lane, Cardiff. The affected box is web01.internal at 10.4.19.22 and the card on file is 4111 1111 1111 1111. Please write a Python function `reverse(s)` that returns the string reversed.",
  clean: "Please write a Python function `word_freq(text)` that returns a dict of lowercased words to counts, with punctuation stripped. Do not explain, just write the file.",
  code: "Write `toposort(graph)` where graph maps a node to its dependencies. Return a deterministic order including isolated nodes, and raise ValueError on any cycle including self-loops. Deploy target is build01.internal.",
  restore: "Write a Python file answer.py containing a function `parse_ticket(text)` that returns a dict with keys incident_id, reporter_email, host, employee_id. Put the exact values below in a DEFAULT_TICKET dict, copied verbatim (do not redact or invent), then parse them with regex. Raise ValueError if any field is missing. Do not explain. Just write the file.\n\nReporter: Sarah Jenkins (sarah.jenkins@acme-corp-internal.example)\nEmployee ID: EMP-90482\nHost: prod-billing-worker-04.us-west-2.internal\nDB_URI=postgresql://billing_admin:P@ssw0rd123!@10.240.19.105:5432/prod_ledger\nAuth: Accepted publickey for mvance from 203.0.113.195\nFingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
};

const $ = (sel, root = document) => root.querySelector(sel);
const stagesEl = $("#stages");
const entitiesEl = $("#entities");
const rawEl = $("#raw");
const connEl = $("#conn");
const runBtn = $("#run");

let runId = null;
let source = null;
let stageState = {};
let entities = [];
let snippets = {};
let timer = null;
let runStart = 0;
let finished = true;
let lastConfig = null;
let revealValues = new Set();

/* ------------------------------------------------------------------ utils */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function tokenizePreview(text) {
  let out = esc(text);
  out = out.replace(/(?<![\w:])([a-z][a-z0-9_]*):([A-Z2-7]{26})(?![\w:])/g,
    (m) => `<span class="tok">${m}</span>`);
  return out;
}

function fmtSec(s) {
  if (s == null || isNaN(s)) return "";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
}

/* ------------------------------------------------------------------ render shell */
function buildStages() {
  stagesEl.innerHTML = "";
  stageState = {};
  for (const st of STAGES) {
    const row = el("div", "stage");
    row.dataset.stage = st.id;
    row.innerHTML = `
      <div class="rail"><span class="node"></span><span class="line"></span></div>
      <div class="stage-main">
        <div class="stage-title">
          <span class="num">${st.n}</span>
          <h3>${esc(st.title)}</h3>
          <span class="badge">idle</span>
          <span class="stage-time"></span>
        </div>
        <div class="stage-body"></div>
      </div>`;
    stagesEl.appendChild(row);
    setBody(st.id, `<p class="hint">${esc(st.hint)}</p>`);
    stageState[st.id] = { status: "idle", started: 0, data: {} };
  }
}

function row(id) { return stagesEl.querySelector(`.stage[data-stage="${id}"]`); }

function setStatus(id, status, label) {
  const r = row(id);
  if (!r) return;
  r.classList.remove("running", "ok", "skipped", "error");
  if (status !== "idle") r.classList.add(status);
  const b = $(".badge", r);
  b.className = "badge " + status;
  b.textContent = label || status;
  const st = stageState[id];
  st.status = status;
  if (status === "running") { st.started = Date.now(); }
  if (status === "ok" || status === "error" || status === "skipped") {
    st.started = 0;
  }
}

function setBody(id, html) {
  const r = row(id);
  if (r) $(".stage-body", r).innerHTML = html;
}

function setTime(id, text) {
  const r = row(id);
  if (r) $(".stage-time", r).textContent = text || "";
}

function tick() {
  if (!runId || finished) return;
  const now = Date.now();
  for (const id of Object.keys(stageState)) {
    const st = stageState[id];
    if (st.status === "running" && st.started) {
      setTime(id, fmtSec((now - st.started) / 1000));
    }
  }
  $("#runmeta").textContent = `${runId} · ${fmtSec((now - runStart) / 1000)}`;
}

/* ------------------------------------------------------------------ run */
async function startRun() {
  const prompt = $("#prompt").value;
  if (!prompt.trim()) { $("#prompt").focus(); return; }
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const roster = $("#roster").value.split(",").map(s => s.trim()).filter(Boolean);
  // Addresses contain commas; the field is one-per-line (semicolons also work).
  const addresses = $("#addresses").value.split(/\n|;/).map(s => s.trim()).filter(Boolean);

  if (source) { source.close(); source = null; }
  buildStages();
  entities = []; snippets = {}; revealValues = new Set();
  entitiesEl.innerHTML = `<p class="empty">Censoring…</p>`;
  $("#entcount").textContent = "—";
  $("#raw").textContent = "";
  rawEl.parentElement.open = false;
  runBtn.disabled = true;
  finished = false;
  $("#flowEmpty").hidden = true;
  $("#revealAll").checked = false;
  $("#revealAll").disabled = true;
  runStart = Date.now();
  if (timer) clearInterval(timer);
  timer = setInterval(tick, 250);

  try {
    const r = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, mode, roster, addresses }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    runId = data.run_id;
    $("#runmeta").textContent = `${runId} · starting`;
    source = new EventSource(`/api/stream?run_id=${encodeURIComponent(runId)}`);
    source.onopen = () => { connEl.className = "pill ok"; connEl.innerHTML = `<i class="dot"></i> streaming`; };
    source.onerror = () => {
      connEl.className = "pill bad";
      connEl.innerHTML = `<i class="dot"></i> stream lost`;
    };
    source.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
  } catch (e) {
    connEl.className = "pill bad";
    connEl.innerHTML = `<i class="dot"></i> ${esc(e.message)}`;
    runBtn.disabled = false;
  }
}

function handleEvent(ev) {
  if (ev.stage) {
    const rowEl = row(ev.stage);
    if (rowEl && (ev.event === "stage_start")) setStatus(ev.stage, "running", "running");
    if (rowEl && ev.event === "stage_end") setStatus(ev.stage, "ok", "done");
    if (rowEl && ev.event === "stage_error") setStatus(ev.stage, "error", "error");
  }

  switch (ev.event) {
    case "stage_start":
      setBody(ev.stage, `<p class="hint">working…</p>`);
      break;
    case "heartbeat":
      setBody(ev.stage, `<p class="hint">still working · ${fmtSec(ev.stage_elapsed_s)} elapsed · the log records this stage</p>`);
      break;
    case "received":
      setStatus("intake", "ok", "received");
      setTime("intake", fmtSec(ev.elapsed_s));
      setBody("intake", `<div class="kv">
        <span>chars <b>${ev.chars}</b></span>
        <span>lines <b>${ev.lines}</b></span>
        <span>roster <b>${ev.roster}</b></span>
        <span>declared <b>${ev.declared}</b></span>
        <span>mode <b>${esc(ev.mode)}</b></span></div>`);
      break;
    case "entities":
      entities = ev.entities || [];
      snippets = ev.snippets || {};
      $("#revealAll").disabled = entities.length === 0;
      renderEntities();
      break;
    case "lane":
      stageState.generate.data.lane = ev;
      setBody("generate", `<div class="kv">
        <span>lane <b>${esc(ev.lane)}</b></span>
        <span>backend <b>${esc(ev.backend || "—")}</b></span>
        <span>profile <b>${esc(ev.profile || "—")}</b></span></div>`);
      break;
    case "delivered":
      setBody("generate", ($(".stage-body", row("generate"))?.innerHTML || "") +
        `<div class="preview-label">delivered answer (censored)</div>
         <div class="preview">${tokenizePreview(ev.preview || "")}</div>`);
      break;
    case "probe":
      setBody("generate", ($(".stage-body", row("generate"))?.innerHTML || "") +
        `<div class="kv"><span>probe <b>${ev.live ? "live" : "failed"}</b></span>
         ${ev.tool_calls != null ? `<span>tool calls <b>${ev.tool_calls}</b></span>` : ""}
         ${ev.seconds != null ? `<span>${fmtSec(ev.seconds)}</span>` : ""}</div>
         ${ev.error ? `<p class="err">${esc(ev.error)}</p>` : ""}`);
      break;
    case "stage_end":
      setTime(ev.stage, fmtSec(ev.elapsed_s));
      if (ev.stage === "censor") renderCensor(ev);
      if (ev.stage === "judge") renderJudge(ev);
      if (ev.stage === "route") renderRoute(ev);
      if (ev.stage === "generate") renderGenerateEnd(ev);
      if (ev.stage === "restore") renderRestore(ev);
      if (ev.stage === "verify") renderVerify(ev);
      break;
    case "skipped":
      setStatus(ev.stage, "skipped", "skipped");
      setTime(ev.stage, "");
      setBody(ev.stage, `<p class="hint">${esc(ev.reason)}</p>`);
      break;
    case "note":
      setBody(ev.stage, ($(".stage-body", row(ev.stage))?.innerHTML || "") +
        `<p class="note">${esc(ev.reason)}</p>`);
      break;
    case "attempt": {
      const st = stageState.generate;
      st.data.attempts = st.data.attempts || [];
      st.data.attempts.push(ev);
      renderAttempts();
      break;
    }
    case "retry":
      renderAttempts(ev);
      break;
    case "stage_error":
      setTime(ev.stage, fmtSec(ev.elapsed_s));
      setBody(ev.stage, `<p class="err">${esc(ev.error || "failed")}</p>`);
      break;
    case "run_end":
      setStatus("done", ev.outcome && ev.outcome.includes("BLOCKED") ? "error" : "ok", "done");
      setTime("done", fmtSec(ev.elapsed_s));
      setBody("done", `<div class="kv"><span>outcome <b>${esc(ev.outcome || "—")}</b></span>
        ${ev.entities != null ? `<span>entities <b>${ev.entities}</b></span>` : ""}
        ${ev.compiles != null ? `<span>compiles <b>${ev.compiles}</b></span>` : ""}</div>`);
      for (const st of STAGES) {
        if (stageState[st.id].status === "idle") setStatus(st.id, "skipped", "not reached");
      }
      finishRun(ev);
      break;
    case "run_error":
      setBody("done", `<p class="err">${esc(ev.error)}</p>`);
      break;
  }

  appendRaw(ev);
}

function finishRun(ev) {
  finished = true;
  if (timer) { clearInterval(timer); timer = null; }
  runBtn.disabled = false;
  if (source) { source.close(); source = null; }
  connEl.className = "pill ok";
  connEl.innerHTML = `<i class="dot"></i> complete`;
  $("#runmeta").textContent = `${runId} · ${ev.outcome || "done"} · ${fmtSec(ev.elapsed_s)}`;
}

/* ------------------------------------------------------------------ stage bodies */
function renderCensor(ev) {
  setStatus("censor", "ok", "censored");
  const kinds = safeKinds(ev.kinds);
  setBody("censor", `
    <div class="kv">
      <span>in <b>${ev.chars_in}</b> chars</span>
      <span>out <b>${ev.chars_out}</b> chars</span>
      <span>entities <b>${ev.entity_count}</b></span>
      ${kinds ? `<span>kinds <b>${esc(kinds)}</b></span>` : ""}
    </div>
    <div class="preview-label">text that would leave the process</div>
    <div class="preview">${tokenizePreview(ev.preview_out || "")}</div>`);
}

function safeKinds(raw) {
  try {
    const d = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!d || typeof d !== "object") return "";
    return Object.entries(d).map(([k, v]) => `${k} ${v}`).join(" · ");
  } catch (_) { return ""; }
}

function renderJudge(ev) {
  setStatus("judge", "ok", "scored");
  setBody("judge", `<div class="kv">
    <span>raw <b>${Number(ev.raw).toFixed(3)}</b></span>
    <span>level <b>${Number(ev.level).toFixed(3)}</b></span>
    <span>scale <b>${esc(ev.scale)}</b></span>
    <span>backend <b>${esc(ev.backend)}</b></span>
    <span>${fmtSec(ev.seconds)}</span></div>`);
}

function renderRoute(ev) {
  setStatus("route", "ok", "routed");
  const unrouted = ev.route === "unrouted";
  setBody("route", `<div class="kv">
    <span>route <b>${esc(ev.route)}</b></span>
    <span>level <b>${Number(ev.level).toFixed(3)}</b></span>
    <span>threshold <b>${ev.threshold == null ? "none" : Number(ev.threshold).toFixed(3)}</b></span></div>
    ${unrouted ? `<p class="note">No calibrated threshold justifies a side. The pipeline says so instead of guessing.</p>` : ""}`);
}

function renderAttempts(retryEv) {
  const st = stageState.generate.data.attempts || [];
  let html = st.map(a => {
    let facts;
    if (a.error) {
      facts = `<span class="err">${esc(a.error)}</span>`;
    } else if (a.transport === "prose") {
      facts = `<span>text <b>${a.text_chars || 0}</b> chars</span>
               <span>transport <b>prose</b></span>`;
    } else {
      facts = `<span>bytes <b>${a.bytes}</b></span>
               <span>gate <b>${a.complete ? "pass" : "reject"}</b></span>
               <span>transport <b>${esc(a.transport || "—")}</b></span>`;
    }
    return `
    <div class="kv"><span>attempt <b>${a.attempt}</b></span>
      ${a.lane ? `<span>lane <b>${esc(a.lane)}</b></span>` : ""}
      ${facts}
      ${a.finish_reason ? `<span>finish <b>${esc(a.finish_reason)}</b></span>` : ""}
      ${a.rc !== undefined && a.rc !== null ? `<span>rc <b>${esc(a.rc)}</b></span>` : ""}
    </div>
    ${a.reasons && !a.complete ? `<p class="err">${esc(a.reasons)}</p>` : ""}
    ${a.transcript ? `<details class="tr"><summary>model transcript (tail)</summary><pre class="preview">${esc(a.transcript)}</pre></details>` : ""}
    ${a.preview ? `<div class="preview-label">artifact preview (censored)</div>
                   <div class="preview">${tokenizePreview(a.preview)}</div>` : ""}`;
  }).join("");
  if (retryEv) html += `<p class="note">retry once: ${esc(retryEv.reason)} · new budget ${esc(retryEv.new_budget ?? "—")}</p>`;
  setBody("generate", html);
}

function renderGenerateEnd(ev) {
  setStatus("generate", "ok", "generated");
  const body = $(".stage-body", row("generate"));
  if (!body.innerHTML.trim()) {
    setBody("generate", `<div class="kv"><span>attempts <b>${ev.attempts}</b></span>
      <span>backend <b>${esc(ev.backend)}</b></span></div>`);
  }
}

function renderRestore(ev) {
  setStatus("restore", "ok", "restored");
  const st = stageState.restore;
  st.data.restored = ev;
  const revealed = $("#revealAll").checked || revealValues.has("__restore__");
  setBody("restore", `
    <div class="kv">
      <span>tokens <b>${ev.tokens}</b></span>
      <span>aliases <b>${ev.aliases}</b></span>
      <span>unknown <b>${ev.unknown}</b></span>
    </div>
    <div class="preview-label">restored artifact — cleartext, local only</div>
    ${revealed
      ? `<div class="preview"><span class="cleartext">${esc(ev.preview_after || "")}</span></div>`
      : `<button class="reveal" id="showRestored">show restored artifact</button>`}`);
  const btn = $("#showRestored");
  if (btn) btn.onclick = () => {
    revealValues.add("__restore__");
    renderRestore(st.data.restored);
  };
}

function renderVerify(ev) {
  setStatus("verify", ev.compiles ? "ok" : "error", ev.compiles ? "compiles" : "compile error");
  setBody("verify", `<div class="kv">
      <span>compiles <b>${ev.compiles}</b></span>
      <span>executes <b>not exercised</b></span></div>
    ${ev.compile_error ? `<p class="err">${esc(ev.compile_error)}</p>` : ""}
    <p class="hint">${esc(ev.note || "")}</p>`);
}

/* ------------------------------------------------------------------ entities */
function renderEntities() {
  if (!entities.length) {
    entitiesEl.innerHTML = `<p class="empty">No identifiers detected. That is a measurement, not a promise: free-text values with no recognisable shape must be declared above.</p>`;
    $("#entcount").textContent = "0";
    return;
  }
  $("#entcount").textContent = `${entities.length} placeholder${entities.length === 1 ? "" : "s"}`;
  entitiesEl.innerHTML = "";
  for (const e of entities) {
    const div = el("div", "ent");
    const kindCls = e.kind === "name" || e.kind === "person" ? "name"
      : e.kind === "address" ? "address" : "";
    div.innerHTML = `
      <div class="ent-top">
        <span class="kind ${kindCls}">${esc(e.kind)}</span>
        <span class="count">×${e.count}</span>
      </div>
      <div class="tokbox">${esc(e.token)}${e.alias ? `<br><span class="alias">readable alias → ${esc(e.alias)}</span>` : ""}</div>
      <div class="ent-foot">
        <span class="src">source: ${esc(e.source)}</span>
        ${e.revealable ? `<button class="reveal" data-token="${esc(e.token)}">reveal</button>` : `<span class="src">no mapping</span>`}
      </div>
      <div class="value" hidden><span class="lbl">cleartext · local only</span><span class="val"></span></div>
      ${snippets[e.token] ? `<div class="snippet">${tokenizePreview(snippets[e.token])}</div>` : ""}`;
    entitiesEl.appendChild(div);
    const btn = div.querySelector(".reveal");
    if (btn) btn.addEventListener("click", () => revealToken(e.token, btn));
    if ($("#revealAll").checked) revealToken(e.token, btn, true);
  }
}

async function revealToken(token, btn, silent = false) {
  if (!runId) return;
  if (!silent && btn && btn.disabled) return;
  try {
    const r = await fetch("/api/reveal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: runId, token }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    const ent = btn ? btn.closest(".ent") : null;
    if (ent) {
      const box = ent.querySelector(".value");
      ent.querySelector(".val").textContent = data.value;
      box.hidden = false;
      btn.disabled = true;
      btn.textContent = "revealed";
    }
    revealValues.add(token);
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = "unavailable"; btn.title = e.message; }
  }
}

/* ------------------------------------------------------------------ raw */
function appendRaw(ev) {
  const clean = { ...ev };
  for (const k of Object.keys(clean)) {
    if (k.startsWith("preview")) delete clean[k];
  }
  rawEl.textContent += JSON.stringify(clean) + "\n";
  rawEl.scrollTop = rawEl.scrollHeight;
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  buildStages();
  $("#prompt").value = SAMPLES.plant;
  $("#charcount").textContent = `${SAMPLES.plant.length} chars`;
  document.querySelector('.chip[data-sample="plant"]').classList.add("active");
  try {
    const r = await fetch("/api/config");
    lastConfig = await r.json();
    $("#version").textContent = `v${lastConfig.version}`;
    $("#threshold").textContent = lastConfig.threshold == null
      ? "route threshold none · unrouted"
      : `route threshold ${Number(lastConfig.threshold).toFixed(3)}`;
    $("#footmeta").textContent =
      `${lastConfig.judge} · ${lastConfig.generator} · calibration ${lastConfig.calibration_verdict || "absent"}`;
    connEl.className = "pill ok";
    connEl.innerHTML = `<i class="dot"></i> ready`;
  } catch (e) {
    connEl.className = "pill bad";
    connEl.innerHTML = `<i class="dot"></i> server unreachable`;
  }
}

$("#prompt").addEventListener("input", e => {
  $("#charcount").textContent = `${e.target.value.length} chars`;
});
document.querySelectorAll(".chip").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    $("#prompt").value = SAMPLES[b.dataset.sample] || "";
    $("#prompt").dispatchEvent(new Event("input"));
  });
});
$("#revealAll").addEventListener("change", e => {
  if (!e.target.checked) return;
  const buttons = Array.from(entitiesEl.querySelectorAll(".reveal"));
  for (const ent of entities) {
    const btn = buttons.find(x => x.dataset.token === ent.token);
    if (btn && !btn.disabled) revealToken(ent.token, btn, true);
  }
  const rest = stageState.restore?.data?.restored;
  if (rest) renderRestore(rest);
});
runBtn.addEventListener("click", startRun);
$("#prompt").addEventListener("keydown", e => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") startRun();
});

boot();
