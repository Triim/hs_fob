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
let state = { chain: [], mempool: [], reputation: [], peers: [] };
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
        ${typeBadge(tx.type)}
        <code class="author" title="${esc(tx.sender.full)}">${esc(tx.sender.short)}</code>
        ${sigBadge(tx)}
        ${loc}
        <code class="txhash" title="${esc(tx.hash)}">${esc(short(tx.hash))}</code>
      </div>`;
    })
    .join("");
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
      return `<div class="block ${hasCert ? "block-cert" : ""}">
        <div class="block-head">
          <span class="bidx">#${b.index}</span>
          <code title="${esc(b.producer.full)}">producer ${esc(b.producer.short || "genesis")}</code>
          <span class="btxs">${b.transactions.length} tx</span>
          <code class="bhash" title="${esc(b.hash)}">${esc(short(b.hash))}</code>
          ${hasCert ? '<span class="cert-flag">★ certificate</span>' : ""}
        </div>
      </div>`;
    })
    .join("");
}

function renderReputation() {
  const el = $("reputation");
  if (!state.reputation.length) {
    el.innerHTML = `<p class="empty">no reputation yet</p>`;
    return;
  }
  el.innerHTML = state.reputation
    .map((r) => {
      const domains = Object.entries(r.weights || {})
        .map(([d, w]) => `<span class="wchip">${esc(d)}: <strong>${w}</strong></span>`)
        .join("");
      return `<div class="rep-row">
        <code title="${esc(r.pubkey.full)}">${esc(r.pubkey.short)}</code>
        <div class="wchips">${domains || '<span class="muted">—</span>'}</div>
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
    if (msg.type && msg.type in state) {
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
