"use strict";
/*
 * Browser console for the competence-attestation chain.
 *
 * The whole app talks to a live node's HTTP bridge (network/http_bridge.py) and
 * signs every write in-browser. The single highest-risk piece is reproducing
 * Python's Transaction.signing_bytes() byte-for-byte; see canonicalJSON() and
 * signingBytes() below.
 */

const ed = window.nobleEd25519;
const sha256 = window.nobleSha256;

// The demo rubric's Merkle root, for the "demo" convenience button.
const DEMO_RUBRIC_ROOT =
  "5fe7ee85958fe7c5110705bb62decde8d1db3b84c0f65e7d718f80f0b494c200";

// ---------------------------------------------------------------- tiny helpers
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const toHex = (u8) => ed.etc.bytesToHex(u8);
const fromHex = (h) => ed.etc.hexToBytes(h);
const short = (s) => (s ? s.slice(0, 12) : "");

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}

/*
 * canonicalJSON — the exact string Python's
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"))
 * produces. Two things JSON.stringify does NOT do that we must:
 *   1. sort object keys *recursively* (Python's sort_keys is deep);
 *   2. no whitespace between tokens (that's separators=(",",":")).
 * Numbers: we only ever put integers here (timestamp is integer seconds,
 * item_index / stake / amount are ints), so JS and Python render them
 * identically. Booleans -> true/false, strings -> JSON-escaped. This is the
 * source of truth for the signed bytes.
 */
function canonicalJSON(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") +
      "}"
    );
  }
  // string, number (int only here), boolean
  return JSON.stringify(v);
}

// Mirror of Transaction.signing_bytes(): canonical JSON of {sender, payload,
// timestamp} (never the signature), UTF-8 encoded.
function signingBytes(tx) {
  const signable = {
    sender: tx.sender,
    payload: tx.payload,
    timestamp: tx.timestamp,
  };
  return enc.encode(canonicalJSON(signable));
}

// Build, sign, and round-trip-verify a transaction. Throws if local verify
// fails (a signing-format regression) so we never POST a tx the node will bounce.
function buildSignedTx(identity, payload) {
  const tx = {
    sender: identity.pub,
    payload,
    // Integer seconds: sidesteps any float-repr divergence between Python's
    // json float formatting and JS. The node stores whatever we send.
    timestamp: Math.floor(Date.now() / 1000),
  };
  const msg = signingBytes(tx);
  const sig = ed.sign(msg, fromHex(identity.priv));
  if (!ed.verify(sig, msg, fromHex(identity.pub))) {
    throw new Error("local signature verify failed — refusing to submit");
  }
  tx.signature = toHex(sig);
  return tx;
}

async function postTx(tx) {
  const res = await fetch(base() + "/api/tx", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(tx),
  });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

function showResult(el, r) {
  if (r.ok) {
    const b = r.body;
    const status = b.status || "ok";
    const h = b.transaction ? ` · <code>${short(b.transaction.hash)}</code>` : "";
    el.className = "result ok";
    el.innerHTML = `✓ ${esc(status)}${h}`;
  } else {
    el.className = "result err";
    el.innerHTML = `✗ ${r.status} — ${esc(r.body.error || "rejected")}`;
  }
}

// ------------------------------------------------------------------ identities
// Each identity: { label, pub (hex), priv (hex) }. Stored in localStorage
// (demo only). currentIndex tracks the active signer.
let identities = [];
let currentIndex = 0;

function loadIdentities() {
  try {
    identities = JSON.parse(localStorage.getItem("identities") || "[]");
  } catch {
    identities = [];
  }
  currentIndex = Number(localStorage.getItem("identityIndex") || 0);
  if (currentIndex >= identities.length) currentIndex = 0;
}

function saveIdentities() {
  localStorage.setItem("identities", JSON.stringify(identities));
  localStorage.setItem("identityIndex", String(currentIndex));
}

function currentId() {
  return identities[currentIndex] || null;
}

function newIdentity(label) {
  const priv = ed.utils.randomPrivateKey();
  const pub = ed.getPublicKey(priv);
  const id = { label: label || `id-${identities.length + 1}`, pub: toHex(pub), priv: toHex(priv) };
  identities.push(id);
  currentIndex = identities.length - 1;
  saveIdentities();
  renderIdentity();
}

function renderIdentity() {
  const sel = $("identity-select");
  sel.innerHTML = identities
    .map((id, i) => `<option value="${i}">${esc(id.label)} · ${esc(short(id.pub))}</option>`)
    .join("");
  sel.value = String(currentIndex);
  const id = currentId();
  $("id-short").textContent = id ? short(id.pub) : "—";
  $("id-short").title = id ? id.pub : "";
  $("id-full").textContent = id ? short(id.pub) : "—";
  $("id-full").title = id ? id.pub : "";
  $("id-label").value = id ? id.label : "";
  updateMyStanding();
  updateAttestWeight();
}

// ---------------------------------------------------------------- node / state
function base() {
  return $("node-select").value;
}

// Latest live state, kept from the WS stream (or GET fallback).
let state = { chain: [], mempool: [], reputation: [], balances: [], peers: [] };
// Validator set + quorum, delivered on the chain event (a function of the prefix).
let consensus = null;
let nodeInfo = null;

// Weight for a pubkey in a domain, read from the reputation snapshot.
function weightOf(pub, domain) {
  const row = state.reputation.find((r) => r.pubkey.full === pub);
  if (!row) return 0;
  return (row.weights && row.weights[domain]) || 0;
}

// Every tx across mined blocks + mempool, tagged with where it lives.
function allTxs() {
  const out = [];
  state.chain.forEach((b) => {
    b.transactions.forEach((tx) =>
      out.push({ tx, where: "block", blockIndex: b.index })
    );
  });
  state.mempool.forEach((tx) => out.push({ tx, where: "mempool", blockIndex: null }));
  return out;
}

// Submissions found anywhere, each with computed weighted support (distinct
// positive attesters matching subject+rubric_root+domain, summed by domain weight).
function submissions() {
  const subs = allTxs().filter((e) => e.tx.type === "submission");
  return subs.map((e) => {
    const p = e.tx.payload;
    const attesters = new Map(); // sender -> weight (dedup by attester)
    allTxs().forEach((a) => {
      const q = a.tx.payload;
      if (a.tx.type !== "attestation") return;
      if (q.subject !== p.subject || q.rubric_root !== p.rubric_root || q.domain !== p.domain)
        return;
      if (q.verdict !== true) return;
      attesters.set(a.tx.sender.full, weightOf(a.tx.sender.full, p.domain));
    });
    let support = 0;
    attesters.forEach((w) => (support += w));
    return { entry: e, payload: p, support, attesterCount: attesters.size };
  });
}

// ------------------------------------------------------------------- rendering
function typeBadge(type) {
  return `<span class="type type-${type}">${type}</span>`;
}

function sigBadge(tx) {
  if (tx.protocol_generated) return `<span class="sig sig-proto">protocol</span>`;
  if (tx.signature_valid) return `<span class="sig sig-ok">✓ valid</span>`;
  return `<span class="sig sig-bad">✗ invalid</span>`;
}

function renderFeed() {
  const entries = allTxs().reverse(); // newest-ish first (mempool then latest blocks)
  $("feed-count").textContent = `${entries.length} tx`;
  const el = $("feed");
  if (!entries.length) {
    el.innerHTML = `<p class="empty">no transactions</p>`;
    return;
  }
  el.innerHTML = entries
    .map(({ tx, where, blockIndex }) => {
      const loc =
        where === "block"
          ? `<span class="loc loc-block">block #${blockIndex}</span>`
          : `<span class="loc loc-pending">pending</span>`;
      return `<div class="feed-row">
        <div class="feed-main">
          ${typeBadge(tx.type)}
          <code class="author" title="${esc(tx.sender.full)}">${esc(tx.sender.short)}</code>
          ${sigBadge(tx)}
          ${loc}
          <code class="txhash" title="${esc(tx.hash)}">${esc(short(tx.hash))}</code>
        </div>
        ${feedDetail(tx)}
      </div>`;
    })
    .join("");
}

// Type-specific extra line: a certificate's contest status, a slash's evidence
// references. Text + color, never color alone.
function feedDetail(tx) {
  if (tx.type === "certificate" && tx.status) {
    const contested = tx.status === "contested";
    return `<div class="feed-detail">
      <span class="cert-status ${contested ? "cert-contested" : "cert-valid"}">
        certificate ${contested ? "⚠ contested" : "✓ valid"}
      </span></div>`;
  }
  if (tx.type === "slash") {
    const p = tx.payload || {};
    const refs = []
      .concat(p.evidence || p.reference || [])
      .filter(Boolean)
      .map((r) => `<code title="${esc(r)}">${esc(short(r))}</code>`)
      .join(" ");
    const off = p.offender ? `offender <code title="${esc(p.offender)}">${esc(short(p.offender))}</code> · ` : "";
    return `<div class="feed-detail slash-detail">
      ${off}−${esc(p.amount ?? "?")} in "${esc(p.domain || "?")}"
      ${refs ? `· evidence ${refs}` : "· no evidence refs"}</div>`;
  }
  return "";
}

function renderChain() {
  $("chain-height").textContent = `height ${state.chain.length}`;
  const el = $("chain");
  if (!state.chain.length) {
    el.innerHTML = `<p class="empty">no blocks</p>`;
    return;
  }
  el.innerHTML = state.chain
    .map((b) => {
      const hasCert = b.transactions.some((t) => t.type === "certificate");
      const isGenesis = b.index === 0;
      // Finality: genesis is final by definition; later blocks carry the fields
      // from the view layer (finalized bool + commits X/N against the quorum).
      const finalized = !!b.finalized;
      const statusCls = isGenesis ? "final" : finalized ? "final" : "pending";
      const statusText = isGenesis ? "✓ genesis (anchor)" : finalized ? "✓ finalized" : "◷ pending";
      const commits =
        b.commits != null && b.validators != null && !isGenesis
          ? `<span class="commits ${finalized ? "commits-met" : ""}">commits ${b.commits}/${b.validators}${b.quorum ? ` · quorum ${b.quorum}` : ""}</span>`
          : "";
      const viewBadge = b.view ? `<span class="view-badge" title="produced in view ${b.view} (view-change)">view ${b.view}</span>` : "";
      return `<div class="block ${finalized || isGenesis ? "block-final" : "block-pending"} ${hasCert ? "block-cert" : ""}">
        <div class="block-head">
          <span class="bidx">#${b.index}</span>
          <span class="fin fin-${statusCls}">${statusText}</span>
          ${commits}
          ${viewBadge}
          ${hasCert ? '<span class="cert-flag">★ certificate</span>' : ""}
        </div>
        <div class="block-sub">
          <code title="${esc(b.producer.full)}">producer ${esc(b.producer.short || "genesis")}</code>
          <span class="btxs">${b.transactions.length} tx</span>
          <code class="bhash" title="${esc(b.hash)}">${esc(short(b.hash))}</code>
        </div>
      </div>`;
    })
    .join("");
}

function renderConsensus() {
  const el = $("consensus");
  const count = $("consensus-quorum");
  if (!consensus || !consensus.validators || !consensus.validators.length) {
    el.innerHTML = `<p class="empty">no validator set yet</p>`;
    count.textContent = "";
    return;
  }
  count.textContent = `N=${consensus.n} · quorum ${consensus.quorum}`;
  const chips = consensus.validators
    .map((v) => `<code class="val-chip" title="${esc(v.full)}">${esc(v.short)}</code>`)
    .join("");
  el.innerHTML = `
    <div class="consensus-summary">
      <span class="cstat"><span class="cstat-n">${consensus.n}</span> validators</span>
      <span class="cstat"><span class="cstat-n">${consensus.quorum}</span> quorum (⌊2n/3⌋+1)</span>
    </div>
    <div class="val-chips">${chips}</div>`;
}

// Merge reputation weights and token balances into one participant table, keyed by
// full pubkey — the reputation snapshot and the balance ledger cover overlapping but
// not identical sets, so a participant may appear with weights, a balance, or both.
function renderReputation() {
  const el = $("reputation");
  const byKey = new Map();
  state.reputation.forEach((r) => {
    byKey.set(r.pubkey.full, { pubkey: r.pubkey, weights: r.weights || {}, bal: null });
  });
  state.balances.forEach((b) => {
    const prev = byKey.get(b.pubkey.full) || { pubkey: b.pubkey, weights: {}, bal: null };
    prev.bal = { total: b.total, locked: b.locked, free: b.free };
    byKey.set(b.pubkey.full, prev);
  });
  const rows = [...byKey.values()];
  if (!rows.length) {
    el.innerHTML = `<p class="empty">no reputation or balances yet</p>`;
    return;
  }
  el.innerHTML = rows
    .map((r) => {
      const domains = Object.entries(r.weights)
        .map(([d, w]) => `<span class="wchip">${esc(d)}: <strong>${w}</strong></span>`)
        .join("");
      const bal = r.bal
        ? `<span class="bal">
             <span class="bal-part" title="total held">total <strong>${r.bal.total}</strong></span>
             <span class="bal-part bal-locked" title="locked as attestation bond">locked <strong>${r.bal.locked}</strong></span>
             <span class="bal-part bal-free" title="free to spend / bond">free <strong>${r.bal.free}</strong></span>
           </span>`
        : `<span class="muted bal-none">baseline balance</span>`;
      return `<div class="rep-row">
        <code title="${esc(r.pubkey.full)}">${esc(r.pubkey.short)}</code>
        <div class="rep-body">
          <div class="wchips">${domains || '<span class="muted">no domain weight</span>'}</div>
          ${bal}
        </div>
      </div>`;
    })
    .join("");
}

function renderReview() {
  const el = $("review-list");
  const threshold = Number($("threshold").value) || 0;
  const subs = submissions();
  if (!subs.length) {
    el.innerHTML = `<p class="empty">no submissions yet</p>`;
  } else {
    el.innerHTML = subs
      .map((s) => {
        const pct = threshold ? Math.min(100, (s.support / threshold) * 100) : 0;
        const met = s.support >= threshold;
        return `<div class="review-item">
          <div class="review-top">
            <strong>${esc(s.payload.title || "(untitled)")}</strong>
            <span class="rdomain">${esc(s.payload.domain)}</span>
            <span class="rloc">${s.entry.where === "block" ? "in chain" : "pending"}</span>
          </div>
          <div class="review-sub">subject <code title="${esc(s.payload.subject)}">${esc(short(s.payload.subject))}</code>
            · ${s.attesterCount} attester(s)</div>
          <div class="bar"><div class="bar-fill ${met ? "met" : ""}" style="width:${pct}%"></div></div>
          <div class="review-num">${s.support} / ${threshold} weighted support ${met ? "✓ threshold met" : ""}</div>
        </div>`;
      })
      .join("");
  }
  refreshAttestSubmissions(subs);
}

// Populate the attest form's submission picker from current submissions.
function refreshAttestSubmissions(subs) {
  const sel = $("att-submission");
  const prev = sel.value;
  sel.innerHTML = subs
    .map((s) => {
      const p = s.payload;
      const v = JSON.stringify({ subject: p.subject, rubric_root: p.rubric_root, domain: p.domain });
      return `<option value='${esc(v)}'>${esc(p.title || "(untitled)")} · ${esc(short(p.subject))} · ${esc(p.domain)}</option>`;
    })
    .join("");
  if (prev) sel.value = prev;
  updateAttestWeight();
}

function updateAttestWeight() {
  const id = currentId();
  const sel = $("att-submission");
  const el = $("att-weight");
  const button = $("btn-attest");
  if (!id || !sel.value) {
    button.disabled = true;
    button.title = !id ? "Create or select an identity first" : "No submission is available to attest";
    el.className = "note";
    el.textContent = !id ? "Select an identity to attest." : "No submission is available to attest.";
    return;
  }
  let domain = "general";
  try {
    domain = JSON.parse(sel.value).domain;
  } catch {}
  const w = weightOf(id.pub, domain);
  if (w > 0) {
    el.className = "note";
    el.textContent = `Your weight in "${domain}": ${w} — this vote carries weight.`;
    button.disabled = false;
    button.title = "";
  } else {
    el.className = "note warn";
    el.textContent = `Your weight in "${domain}" is 0 — attestation is unavailable until you have domain weight.`;
    button.disabled = true;
    button.title = `Attestation requires reputation weight in "${domain}"`;
  }
}

function updateMyStanding() {
  const id = currentId();
  const el = $("my-standing");
  if (!id) {
    el.innerHTML = "";
    return;
  }
  const row = state.reputation.find((r) => r.pubkey.full === id.pub);
  if (!row || !Object.keys(row.weights || {}).length) {
    el.innerHTML = `<span class="muted">no reputation weight yet in any domain</span>`;
    return;
  }
  el.innerHTML =
    "standing: " +
    Object.entries(row.weights)
      .map(([d, w]) => `<span class="wchip">${esc(d)}: <strong>${w}</strong></span>`)
      .join(" ");
}

function renderNodeAuthority() {
  const el = $("mine-authority");
  const button = $("btn-mine");
  if (!nodeInfo) {
    el.textContent = "node info unavailable";
    button.disabled = true;
    button.title = "Node authority status is unavailable";
    return;
  }
  if (nodeInfo.is_authority) {
    el.className = "note ok";
    el.innerHTML = `This node <strong>is an authority</strong> (producer <code>${esc(nodeInfo.producer.short)}</code>). Mining will produce a valid block from its mempool.`;
    button.disabled = false;
    button.title = "";
  } else {
    el.className = "note warn";
    el.innerHTML = `This node is <strong>not an authority</strong> (producer <code>${esc(nodeInfo.producer.short)}</code>). Mining is unavailable because peers would reject its block.`;
    button.disabled = true;
    button.title = "Only an authority node can produce an accepted block";
  }
}

function renderAll() {
  renderConsensus();
  renderFeed();
  renderChain();
  renderReputation();
  renderReview();
  updateMyStanding();
}

// ------------------------------------------------------------------- websocket
let ws = null;
let wsRetry = null;

function setConn(text, cls) {
  const el = $("conn-status");
  el.textContent = text;
  el.className = "pill " + cls;
}

function connectWS() {
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }
  clearTimeout(wsRetry);
  const url = base().replace(/^http/, "ws") + "/ws";
  setConn("connecting…", "pill-muted");
  let sock;
  try {
    sock = new WebSocket(url);
  } catch {
    scheduleReconnect();
    return;
  }
  ws = sock;
  sock.onopen = () => setConn("live · " + base().replace(/^https?:\/\//, ""), "pill-ok");
  sock.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (msg.type === "chain") {
      state.chain = msg.chain;
      // The validator set + quorum ride on the chain event (see http_bridge).
      if (msg.consensus) consensus = msg.consensus;
      renderAll();
    } else if (msg.type && msg.type in state) {
      state[msg.type] = msg[msg.type];
      renderAll();
    }
  };
  sock.onclose = () => {
    if (ws === sock) {
      setConn("disconnected — retrying", "pill-bad");
      scheduleReconnect();
    }
  };
  sock.onerror = () => { try { sock.close(); } catch {} };
}

function scheduleReconnect() {
  clearTimeout(wsRetry);
  wsRetry = setTimeout(connectWS, 1500);
}

// Fetch /api/node (not part of the WS stream) whenever we (re)connect / switch.
async function refreshNodeInfo() {
  try {
    const res = await fetch(base() + "/api/node");
    nodeInfo = await res.json();
  } catch {
    nodeInfo = null;
  }
  renderNodeAuthority();
}

function switchNode() {
  connectWS();
  refreshNodeInfo();
  fetchScenarios();
}

// ---------------------------------------------------------------- scenarios
let scenarioRunning = false;

// Order + human labels for the scenario buttons (any scenario the node reports
// that isn't listed here still gets a button, using its own name).
const SCENARIO_LABELS = {
  sunny: "☀ Sunny — honest cert",
  rainy: "🌧 Rainy — forged rubric",
  slash: "⚖ Slash — equivocation",
  view_change: "🔄 View-change — proposer offline",
  collusion: "🕸 Collusion — cap clamps",
};

async function fetchScenarios() {
  const box = $("scenario-buttons");
  try {
    const res = await fetch(base() + "/api/scenarios");
    if (!res.ok) {
      box.innerHTML = `<span class="muted">This node exposes no scenarios — switch to <strong>node 0</strong> to run them.</span>`;
      return;
    }
    const list = await res.json();
    box.innerHTML = list
      .map(
        (s) =>
          `<button class="scenario-btn" data-scenario="${esc(s.name)}" title="${esc(s.description)}">${esc(SCENARIO_LABELS[s.name] || s.name)}</button>`
      )
      .join("");
    box.querySelectorAll(".scenario-btn").forEach((btn) =>
      btn.addEventListener("click", () => runScenario(btn.dataset.scenario))
    );
  } catch {
    box.innerHTML = `<span class="muted">Could not reach this node's scenario list.</span>`;
  }
}

async function runScenario(name) {
  if (scenarioRunning) return;
  scenarioRunning = true;
  const log = $("scenario-log");
  const buttons = $("scenario-buttons").querySelectorAll(".scenario-btn");
  buttons.forEach((b) => (b.disabled = true));
  log.innerHTML = `<p class="scenario-running">Running <strong>${esc(name)}</strong> against the live network…</p>`;
  try {
    const res = await fetch(base() + "/api/scenario/" + encodeURIComponent(name), {
      method: "POST",
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      log.innerHTML = `<p class="result err">✗ ${res.status} — ${esc(body.error || "scenario failed")}</p>`;
    } else {
      renderScenarioResult(body);
    }
  } catch (e) {
    log.innerHTML = `<p class="result err">✗ ${esc(e.message)}</p>`;
  } finally {
    scenarioRunning = false;
    buttons.forEach((b) => (b.disabled = false));
  }
}

// The headline verdict chips for a finished scenario — the one thing to read first.
function scenarioVerdicts(r) {
  const chips = [];
  if (r.certificate_issued != null) {
    const yes = r.certificate_issued;
    chips.push(
      `<span class="verdict ${yes ? "v-ok" : "v-no"}">${yes ? "✓ certificate issued" : "✗ no certificate"}</span>`
    );
  }
  chips.push(
    `<span class="verdict ${r.finalized ? "v-ok" : "v-warn"}">${r.finalized ? "✓ tip finalized" : "◷ tip pending"}</span>`
  );
  chips.push(`<span class="verdict v-info">height ${r.chain_height}</span>`);
  // Scenario-specific highlights.
  if (r.support_before != null && r.support_after != null) {
    chips.push(`<span class="verdict v-info">support ${r.support_before} → ${r.support_after}</span>`);
  }
  if (r.raw_support != null && r.capped_support != null) {
    chips.push(`<span class="verdict v-info">support ${r.raw_support} → capped ${r.capped_support}</span>`);
  }
  if (r.node_down) {
    chips.push(`<span class="verdict v-warn" title="${esc(r.node_down.pubkey)}">node ${r.node_down.index} offline</span>`);
  }
  if (r.commits != null && r.validators != null) {
    chips.push(`<span class="verdict v-ok">commits ${r.commits}/${r.validators} · quorum ${r.quorum}</span>`);
  }
  return chips.join("");
}

function scenarioTables(r) {
  let out = "";
  // Balances that moved (total/locked/free) — makes the bond lifecycle visible.
  if (r.balances && Object.keys(r.balances).length) {
    const rows = Object.entries(r.balances)
      .map(
        ([name, b]) =>
          `<tr><td>${esc(name)}</td><td>${b.total}</td><td class="bal-locked">${b.locked}</td><td class="bal-free">${b.free}</td></tr>`
      )
      .join("");
    out += `<div class="scenario-table">
      <div class="st-title">Token balances (total / locked / free)</div>
      <table><thead><tr><th>who</th><th>total</th><th>locked</th><th>free</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`;
  }
  if (r.reputation && Object.keys(r.reputation).length) {
    const rows = Object.entries(r.reputation)
      .map(([name, w]) => {
        const cells = Object.entries(w)
          .map(([d, v]) => `<span class="wchip">${esc(d)}: <strong>${v}</strong></span>`)
          .join(" ");
        return `<tr><td>${esc(name)}</td><td>${cells}</td></tr>`;
      })
      .join("");
    out += `<div class="scenario-table">
      <div class="st-title">Reputation weight</div>
      <table><tbody>${rows}</tbody></table>
    </div>`;
  }
  return out;
}

function renderScenarioResult(r) {
  const steps = (r.steps || [])
    .map(
      (s) =>
        `<li><span class="step-n">${s.step}</span><span class="step-d">${esc(s.detail)}</span></li>`
    )
    .join("");
  $("scenario-log").innerHTML = `
    <div class="scenario-result">
      <div class="scenario-verdicts"><strong class="scenario-name">${esc(r.scenario)}</strong>${scenarioVerdicts(r)}</div>
      <ol class="step-log">${steps}</ol>
      <div class="scenario-tables">${scenarioTables(r)}</div>
    </div>`;
}

// ---------------------------------------------------------------- self-test
// Prove the signing format is intact before any writes: generate an ephemeral
// key, sign a fixed tx, verify locally, and show the canonical bytes.
function runSelfTest() {
  const el = $("selftest");
  try {
    const priv = ed.utils.randomPrivateKey();
    const pub = ed.getPublicKey(priv);
    const tx = {
      sender: toHex(pub),
      payload: { type: "submission", subject: toHex(pub), domain: "general", rubric_root: "ab", title: "t", artifact_hash: "cd", artifact_name: "" },
      timestamp: 1700000000,
    };
    const msg = signingBytes(tx);
    const sig = ed.sign(msg, priv);
    const ok = ed.verify(sig, msg, pub);
    if (!ok) throw new Error("verify returned false");
    el.className = "selftest ok";
    el.innerHTML = `✓ signing self-test passed — sign→verify round-trips locally. Canonical bytes look like: <code>${esc(new TextDecoder().decode(msg).slice(0, 80))}…</code>`;
  } catch (e) {
    el.className = "selftest err";
    el.textContent = "✗ signing self-test FAILED: " + e.message;
  }
}

// ------------------------------------------------------------------ file hash
async function hashFile(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  return toHex(sha256(buf)); // matches hash_artifact (SHA-256 hex), no WebCrypto needed
}

// --------------------------------------------------------------------- wiring
function wire() {
  $("node-select").addEventListener("change", switchNode);

  $("btn-new-identity").addEventListener("click", () => {
    const label = prompt("Label for this identity?", `id-${identities.length + 1}`);
    if (label === null) return;
    newIdentity(label.trim());
  });
  $("identity-select").addEventListener("change", (e) => {
    currentIndex = Number(e.target.value);
    saveIdentities();
    renderIdentity();
  });
  $("btn-del-identity").addEventListener("click", () => {
    if (!identities.length) return;
    if (!confirm("Delete this identity? Its key is lost.")) return;
    identities.splice(currentIndex, 1);
    currentIndex = 0;
    saveIdentities();
    if (!identities.length) newIdentity("id-1");
    else renderIdentity();
  });
  $("btn-rename").addEventListener("click", () => {
    const id = currentId();
    if (!id) return;
    id.label = $("id-label").value.trim() || id.label;
    saveIdentities();
    renderIdentity();
  });

  $("btn-demo-rubric").addEventListener("click", () => {
    $("sub-rubric").value = DEMO_RUBRIC_ROOT;
  });

  $("sub-file").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    $("sub-hash").textContent = "hashing…";
    $("sub-hash").textContent = await hashFile(f);
    $("sub-hash").title = $("sub-hash").textContent;
    if (!$("sub-title").value) $("sub-title").value = f.name;
  });

  $("btn-submit").addEventListener("click", async () => {
    const id = currentId();
    const el = $("submit-result");
    if (!id) return void (el.className = "result err", (el.textContent = "no identity"));
    const artifact_hash = $("sub-hash").textContent;
    if (!/^[0-9a-f]{64}$/.test(artifact_hash))
      return void (el.className = "result err", (el.textContent = "pick a file first"));
    const f = $("sub-file").files[0];
    const payload = {
      type: "submission",
      subject: id.pub, // sender == subject for submissions
      domain: $("sub-domain").value.trim(),
      rubric_root: $("sub-rubric").value.trim(),
      title: $("sub-title").value.trim(),
      artifact_hash,
      artifact_name: f ? f.name : "",
    };
    try {
      const tx = buildSignedTx(id, payload);
      showResult(el, await postTx(tx));
    } catch (e) {
      el.className = "result err";
      el.textContent = e.message;
    }
  });

  $("att-submission").addEventListener("change", updateAttestWeight);
  $("btn-attest").addEventListener("click", async () => {
    const id = currentId();
    const el = $("attest-result");
    const sel = $("att-submission");
    if (!id) return void (el.className = "result err", (el.textContent = "no identity"));
    if (!sel.value)
      return void (el.className = "result err", (el.textContent = "no submission selected"));
    const ref = JSON.parse(sel.value);
    const payload = {
      type: "attestation",
      subject: ref.subject,
      rubric_root: ref.rubric_root,
      domain: ref.domain,
      item_index: parseInt($("att-item").value, 10),
      verdict: $("att-verdict").value === "true",
      stake: parseInt($("att-stake").value, 10),
    };
    try {
      const tx = buildSignedTx(id, payload);
      showResult(el, await postTx(tx));
    } catch (e) {
      el.className = "result err";
      el.textContent = e.message;
    }
  });

  $("btn-mine").addEventListener("click", async () => {
    const el = $("mine-result");
    el.className = "result";
    el.textContent = "mining…";
    try {
      const res = await fetch(base() + "/api/mine", { method: "POST" });
      const body = await res.json().catch(() => ({}));
      if (res.ok) {
        el.className = "result ok";
        el.innerHTML =
          body.status === "produced"
            ? `✓ produced block #${body.block.index} (${body.block.transactions.length} tx) → ${body.broadcast_to} peer(s)`
            : `· ${esc(body.message || body.status)}`;
      } else {
        el.className = "result err";
        el.textContent = "✗ " + (body.error || res.status);
      }
    } catch (e) {
      el.className = "result err";
      el.textContent = e.message;
    }
  });

  $("btn-slash").addEventListener("click", async () => {
    const id = currentId();
    const el = $("slash-result");
    if (!id) return void (el.className = "result err", (el.textContent = "no identity"));
    const payload = {
      type: "slash",
      offender: $("slash-offender").value.trim(),
      domain: $("slash-domain").value.trim(),
      amount: parseInt($("slash-amount").value, 10),
      reason: $("slash-reason").value.trim(),
      reference: $("slash-ref").value.trim(),
    };
    try {
      const tx = buildSignedTx(id, payload);
      showResult(el, await postTx(tx));
    } catch (e) {
      el.className = "result err";
      el.textContent = e.message;
    }
  });

  $("threshold").addEventListener("input", renderReview);
}

// ----------------------------------------------------------------------- init
function init() {
  if (!ed || !sha256) {
    $("selftest").className = "selftest err";
    $("selftest").textContent = "✗ noble-ed25519 bundle failed to load";
    return;
  }
  runSelfTest();
  loadIdentities();
  if (!identities.length) newIdentity("id-1");
  renderIdentity();
  wire();
  switchNode();
}

init();
