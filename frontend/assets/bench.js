"use strict";
/*
 * Benchmarking tab — runs the live consensus benchmarks and charts their results.
 *
 * Independent of app.js (like tabs.js): it touches no demo state. Each screen has
 * a Run button that POSTs one benchmark endpoint on **node 0** (the only node that
 * carries them) and renders the returned raw per-run data through MiniChart.
 *
 *   POST /api/benchmark/finality     — finalization time vs validator count
 *   POST /api/benchmark/convergence  — finality → all-nodes-agree window
 *   POST /api/benchmark/view_change  — happy path vs a rotated stalled proposer
 *
 * Every number in the response is a difference between consensus-event timestamps
 * recorded inside the nodes (block proposed / quorum first observed / view-change
 * vote cast) — see network/benchmarks.py. Runs take seconds to tens of seconds, so
 * the button enters a "running…" state with an elapsed counter until the response
 * lands, then the chart and summary table are drawn in one go.
 */
(function () {
  const $ = (id) => document.getElementById(id);

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
    );
  }

  const round = (v) => (typeof v === "number" ? Math.round(v * 100) / 100 : "—");
  const ratio = (value, baseline) =>
    typeof value === "number" && typeof baseline === "number" && baseline > 0
      ? `${round(value / baseline)}×`
      : "—";
  const median = (values) => {
    const sorted = values.filter((v) => typeof v === "number").sort((a, b) => a - b);
    if (!sorted.length) return null;
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  };

  /*
   * Benchmarks live on node 0 only. Use the demo's node selector's FIRST option
   * (node 0) if the page has one, so a redeployment that moves the port is picked
   * up automatically; otherwise fall back to the documented default.
   */
  function benchBase() {
    const select = $("node-select");
    if (select && select.options.length) return select.options[0].value;
    return "http://127.0.0.1:8080";
  }

  // Chart canvases are sized in CSS; redraw stores the last render so a resize (or
  // the tab being shown after a run) repaints at the right pixel size.
  const lastRender = {};

  function summaryTable(rows) {
    return `<table class="bench-table">
      <thead><tr>${rows.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
      <tbody>${rows.body
        .map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`)
        .join("")}</tbody>
    </table>`;
  }

  // ------------------------------------------------------------------ renderers

  function renderFinality(screen, data) {
    const baseline = data.series[0] && data.series[0].median;
    const points = data.series.map((s) => ({
      label: `N=${s.n}`,
      median: s.median,
      min: s.min,
      max: s.max,
    }));
    lastRender.finality = (canvas) =>
      window.MiniChart.drawSpreadSeries(canvas, points, {
        xTitle: "validators (N) — each on its own cluster",
        yTitle: "finalization time (ms)",
      });
    lastRender.finality($(`bench-canvas-finality`));

    $("bench-summary-finality").innerHTML = summaryTable({
      head: ["N", "quorum", "median ms", "vs N=4", "min ms", "max ms", "p95 ms", "blocks"],
      body: data.series.map((s) => [
        s.n,
        s.quorum,
        round(s.median),
        ratio(s.median, baseline),
        round(s.min),
        round(s.max),
        round(s.p95),
        s.runs,
      ]),
    });
  }

  function renderConvergence(screen, data) {
    const values = data.runs.map((r) => r.spread_ms).filter((v) => typeof v === "number");
    const finalityMedian = median(data.runs.map((r) => r.finality_ms));
    lastRender.convergence = (canvas) =>
      window.MiniChart.drawScatter(canvas, values, {
        median: data.summary.median,
        p95: data.summary.p95,
        xTitle: "finalized block (run)",
        yTitle: "agreement window (ms)",
      });
    lastRender.convergence($("bench-canvas-convergence"));

    $("bench-summary-convergence").innerHTML =
      summaryTable({
        head: ["metric", "median ms", "vs finality", "p95 ms", "max ms", "min ms", "runs"],
        body: [
          [
            "proposer block finality",
            round(finalityMedian),
            "1× baseline",
            "—",
            "—",
            "—",
            data.runs.filter((r) => typeof r.finality_ms === "number").length,
          ],
          [
            "network agreement window",
            round(data.summary.median),
            ratio(data.summary.median, finalityMedian),
            round(data.summary.p95),
            round(data.summary.max),
            round(data.summary.min),
            data.summary.runs,
          ],
          [
            "after the proposer's own finality",
            round(data.proposer_relative.median),
            ratio(data.proposer_relative.median, finalityMedian),
            round(data.proposer_relative.p95),
            round(data.proposer_relative.max),
            round(data.proposer_relative.min),
            data.proposer_relative.runs,
          ],
        ],
      }) +
      `<p class="bench-note">Measured on the running cluster of ${esc(data.nodes)} nodes
       (quorum ${esc(data.quorum)}). Per-block finality on the proposer:
       ${esc(
         data.runs
           .map((r) => (typeof r.finality_ms === "number" ? round(r.finality_ms) : "—"))
           .join(" · ")
       )} ms.</p>`;
  }

  function renderViewChange(screen, data) {
    const normal = data.groups.find((g) => g.label === "normal");
    const groups = data.groups.map((g) => ({
      label: g.label === "normal" ? "normal (view 0)" : "view-change (rotated)",
      median: g.median,
      min: g.min,
      max: g.max,
    }));
    lastRender.view_change = (canvas) =>
      window.MiniChart.drawGroupedBars(canvas, groups, {
        xTitle: `N=${data.n} validators, quorum ${data.quorum}`,
        yTitle: "time to finality (ms)",
      });
    lastRender.view_change($("bench-canvas-view_change"));

    const rows = data.groups.map((g) => [
      g.label,
      round(g.median),
      ratio(g.median, normal && normal.median),
      round(g.min),
      round(g.max),
      round(g.p95),
      g.runs,
    ]);
    const vc = data.view_change_propose_only;
    $("bench-summary-view_change").innerHTML =
      summaryTable({
        head: ["path", "median ms", "vs happy path", "min ms", "max ms", "p95 ms", "runs"],
        body: rows,
      }) +
      `<p class="bench-note">The view-change row is measured from the stall being acted on
       (the first validator's view-change vote) to the replacement block's finality. The
       rotated block's own propose→finalize time is ${esc(round(vc.median))} ms median —
       the difference is the vote round that justifies the new view.</p>`;
  }

  const RENDERERS = {
    finality: renderFinality,
    convergence: renderConvergence,
    view_change: renderViewChange,
  };

  // --------------------------------------------------------------------- runner

  let running = false;

  async function run(name, params) {
    if (running) return;
    running = true;
    const button = document.querySelector(`.bench-run[data-bench="${name}"]`);
    const status = $(`bench-status-${name}`);
    document.querySelectorAll(".bench-run").forEach((b) => (b.disabled = true));
    button.classList.add("busy");

    const started = Date.now();
    const tick = setInterval(() => {
      status.textContent = `running… ${Math.round((Date.now() - started) / 1000)}s elapsed — real nodes, real blocks`;
    }, 250);
    status.className = "bench-status running";
    status.textContent = "running… starting nodes";

    try {
      const res = await fetch(benchBase() + "/api/benchmark/" + name, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params || {}),
      });
      const data = await res.json();
      if (!res.ok) {
        status.className = "bench-status err";
        status.textContent = `✗ ${res.status} — ${data.error || "benchmark failed"}`;
        return;
      }
      RENDERERS[name](name, data);
      status.className = "bench-status ok";
      status.textContent = `✓ done in ${Math.round(data.elapsed_s)}s — ${data.metric}`;
    } catch (err) {
      status.className = "bench-status err";
      status.textContent =
        `✗ could not reach ${benchBase()} — start the nodes with ` +
        `"uv run python -m network.run_nodes" (benchmarks live on node 0).`;
    } finally {
      clearInterval(tick);
      running = false;
      document.querySelectorAll(".bench-run").forEach((b) => (b.disabled = false));
      button.classList.remove("busy");
    }
  }

  function wire() {
    document.querySelectorAll(".bench-run").forEach((btn) =>
      btn.addEventListener("click", () => {
        const params = {};
        const repeats = document.querySelector(`.bench-repeats[data-bench="${btn.dataset.bench}"]`);
        if (repeats && repeats.value) params.repeats = Number(repeats.value);
        run(btn.dataset.bench, params);
      })
    );
    // A canvas sized in CSS needs a repaint when its box changes (window resize,
    // or the tab being revealed after a run happened on a hidden panel).
    window.addEventListener("resize", () => {
      Object.keys(lastRender).forEach((name) => {
        const canvas = $(`bench-canvas-${name}`);
        if (canvas && canvas.offsetParent !== null) lastRender[name](canvas);
      });
    });
    const nav = document.querySelector("nav.tabs");
    if (nav) {
      nav.addEventListener("click", () => {
        setTimeout(() => {
          Object.keys(lastRender).forEach((name) => {
            const canvas = $(`bench-canvas-${name}`);
            if (canvas && canvas.offsetParent !== null) lastRender[name](canvas);
          });
        }, 30);
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
