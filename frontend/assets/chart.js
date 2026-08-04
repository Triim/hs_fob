"use strict";
/*
 * Minimal canvas charting — vendored, dependency-free, offline.
 *
 * Three chart forms, exactly the ones the Benchmarking tab needs:
 *   drawSpreadSeries — median point + min–max whisker per category, connected
 *                      (finality time vs validator count);
 *   drawScatter      — one point per run + median / p95 reference lines
 *                      (convergence latency distribution);
 *   drawGroupedBars  — one bar per group with a min–max whisker
 *                      (normal vs view-change finalization time).
 *
 * Everything is drawn on a 2-D context scaled by devicePixelRatio, so the lines
 * stay crisp on retina displays. Colors come from the page's CSS custom
 * properties, so the charts follow the site's light theme rather than restating
 * it. Numbers are rounded before they are drawn — no raw float ever reaches an
 * axis label.
 */
(function () {
  const AXIS_FONT = "12px ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif";
  const LABEL_FONT = "600 12px ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif";
  // Left padding fits a five-digit millisecond label plus the rotated axis title.
  const PAD = { top: 22, right: 18, bottom: 42, left: 74 };

  function css(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function theme() {
    return {
      accent: css("--accent", "#0f766e"),
      accentWeak: css("--accent-weak", "#edfbf8"),
      line: css("--line", "#e4e6ea"),
      lineStrong: css("--line-strong", "#d3d7de"),
      text: css("--text", "#1a1a1a"),
      muted: css("--muted", "#616875"),
      warn: css("--warn", "#b45309"),
      info: css("--info", "#1d4ed8"),
    };
  }

  // Prepare a device-pixel-ratio-scaled context sized to the canvas' CSS box.
  function setup(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(280, Math.round(rect.width || canvas.clientWidth || 640));
    const h = Math.max(180, Math.round(rect.height || canvas.clientHeight || 320));
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h, t: theme() };
  }

  // A "nice" axis maximum at or just above the data max, so gridline labels are
  // round numbers without leaving half the plot empty (a plain 1/2/5 ladder would
  // put a 11.5k maximum on a 20k axis).
  const NICE_STEPS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
  function niceMax(value) {
    if (!(value > 0)) return 1;
    const base = Math.pow(10, Math.floor(Math.log10(value)));
    const scaled = value / base;
    return (NICE_STEPS.find((s) => scaled <= s) || 10) * base;
  }

  function fmt(value) {
    if (value === null || value === undefined || Number.isNaN(value)) return "—";
    if (value === 0) return "0";
    if (value >= 1000) return String(Math.round(value));
    if (value >= 100) return value.toFixed(0);
    if (value >= 10) return value.toFixed(1);
    return value.toFixed(2);
  }

  // Axes, horizontal gridlines with rounded labels, and the two axis titles.
  function frame(ctx, w, h, t, max, xTitle, yTitle) {
    const plot = {
      x0: PAD.left,
      y0: PAD.top,
      x1: w - PAD.right,
      y1: h - PAD.bottom,
    };
    plot.width = plot.x1 - plot.x0;
    plot.height = plot.y1 - plot.y0;

    ctx.font = AXIS_FONT;
    ctx.textBaseline = "middle";
    const ticks = 5;
    for (let i = 0; i <= ticks; i++) {
      const value = (max / ticks) * i;
      const y = plot.y1 - (plot.height / ticks) * i;
      ctx.strokeStyle = i === 0 ? t.lineStrong : t.line;
      ctx.beginPath();
      ctx.moveTo(plot.x0, y + 0.5);
      ctx.lineTo(plot.x1, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = t.muted;
      ctx.textAlign = "right";
      // Whole milliseconds on a large axis (0 / 80 / 160 …), decimals only when the
      // whole range is sub-10ms and rounding would collapse the ticks together.
      ctx.fillText(max >= 10 ? String(Math.round(value)) : fmt(value), plot.x0 - 8, y);
    }

    ctx.strokeStyle = t.lineStrong;
    ctx.beginPath();
    ctx.moveTo(plot.x0 + 0.5, plot.y0);
    ctx.lineTo(plot.x0 + 0.5, plot.y1);
    ctx.stroke();

    ctx.fillStyle = t.muted;
    ctx.textAlign = "center";
    ctx.fillText(xTitle, plot.x0 + plot.width / 2, h - 12);
    ctx.save();
    ctx.translate(14, plot.y0 + plot.height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText(yTitle, 0, 0);
    ctx.restore();

    plot.yOf = (v) => plot.y1 - (Math.max(0, v) / max) * plot.height;
    return plot;
  }

  function dot(ctx, x, y, r, fill, stroke) {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = fill;
    ctx.fill();
    if (stroke) {
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }

  function whisker(ctx, x, yLow, yHigh, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x, yLow);
    ctx.lineTo(x, yHigh);
    ctx.moveTo(x - 5, yLow);
    ctx.lineTo(x + 5, yLow);
    ctx.moveTo(x - 5, yHigh);
    ctx.lineTo(x + 5, yHigh);
    ctx.stroke();
  }

  /*
   * points: [{label, median, min, max}] — median connected across categories,
   * each with a min–max whisker. Used for finalization time vs validator count.
   */
  function drawSpreadSeries(canvas, points, opts) {
    opts = opts || {};
    const { ctx, w, h, t } = setup(canvas);
    const usable = points.filter((p) => p.median !== null && p.median !== undefined);
    if (!usable.length) return emptyState(ctx, w, h, t);

    const max = niceMax(Math.max(...usable.map((p) => p.max ?? p.median)) * 1.15);
    const plot = frame(ctx, w, h, t, max, opts.xTitle || "", opts.yTitle || "ms");
    const step = plot.width / usable.length;
    const xOf = (i) => plot.x0 + step * (i + 0.5);

    ctx.strokeStyle = t.accent;
    ctx.lineWidth = 2;
    ctx.beginPath();
    usable.forEach((p, i) => {
      const x = xOf(i);
      const y = plot.yOf(p.median);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.font = LABEL_FONT;
    usable.forEach((p, i) => {
      const x = xOf(i);
      if (p.min !== null && p.max !== null && p.min !== undefined) {
        whisker(ctx, x, plot.yOf(p.min), plot.yOf(p.max), t.lineStrong);
      }
      dot(ctx, x, plot.yOf(p.median), 4.5, "#ffffff", t.accent);
      ctx.fillStyle = t.text;
      ctx.textAlign = "center";
      ctx.textBaseline = "bottom";
      ctx.fillText(fmt(p.median), x, plot.yOf(p.median) - 10);
      ctx.fillStyle = t.muted;
      ctx.textBaseline = "top";
      ctx.font = AXIS_FONT;
      ctx.fillText(String(p.label), x, plot.y1 + 8);
      ctx.font = LABEL_FONT;
    });
  }

  /*
   * values: [number] — one point per run, plus optional median / p95 reference
   * lines. Used for the convergence-latency distribution.
   */
  function drawScatter(canvas, values, opts) {
    opts = opts || {};
    const { ctx, w, h, t } = setup(canvas);
    const usable = values.filter((v) => typeof v === "number" && !Number.isNaN(v));
    if (!usable.length) return emptyState(ctx, w, h, t);

    const max = niceMax(Math.max(...usable, opts.p95 || 0) * 1.25 || 1);
    const plot = frame(ctx, w, h, t, max, opts.xTitle || "run", opts.yTitle || "ms");
    const step = plot.width / usable.length;

    [["median", opts.median, t.accent], ["p95", opts.p95, t.warn]].forEach(([name, value, color]) => {
      if (typeof value !== "number") return;
      const y = plot.yOf(value);
      ctx.save();
      ctx.setLineDash([5, 4]);
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(plot.x0, y);
      ctx.lineTo(plot.x1, y);
      ctx.stroke();
      ctx.restore();
      ctx.font = LABEL_FONT;
      ctx.fillStyle = color;
      ctx.textAlign = "right";
      ctx.textBaseline = "bottom";
      ctx.fillText(`${name} ${fmt(value)}`, plot.x1, y - 4);
    });

    usable.forEach((v, i) => {
      const x = plot.x0 + step * (i + 0.5);
      dot(ctx, x, plot.yOf(v), 4, t.accentWeak, t.accent);
      ctx.font = AXIS_FONT;
      ctx.fillStyle = t.muted;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillText(String(i + 1), x, plot.y1 + 8);
    });
  }

  /*
   * groups: [{label, median, min, max}] — one bar per group with a min–max
   * whisker. Used for normal vs view-change finalization time.
   */
  function drawGroupedBars(canvas, groups, opts) {
    opts = opts || {};
    const { ctx, w, h, t } = setup(canvas);
    const usable = groups.filter((g) => typeof g.median === "number");
    if (!usable.length) return emptyState(ctx, w, h, t);

    const max = niceMax(Math.max(...usable.map((g) => g.max ?? g.median)) * 1.2);
    const plot = frame(ctx, w, h, t, max, opts.xTitle || "", opts.yTitle || "ms");
    const step = plot.width / usable.length;
    const barWidth = Math.min(120, step * 0.45);
    const colors = [t.accent, t.warn];

    usable.forEach((g, i) => {
      const cx = plot.x0 + step * (i + 0.5);
      const y = plot.yOf(g.median);
      const color = colors[i % colors.length];
      ctx.fillStyle = color;
      ctx.globalAlpha = 0.18;
      ctx.fillRect(cx - barWidth / 2, y, barWidth, plot.y1 - y);
      ctx.globalAlpha = 1;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.strokeRect(cx - barWidth / 2, y, barWidth, plot.y1 - y);
      if (typeof g.min === "number" && typeof g.max === "number") {
        whisker(ctx, cx, plot.yOf(g.min), plot.yOf(g.max), t.lineStrong);
      }
      ctx.font = LABEL_FONT;
      ctx.fillStyle = t.text;
      ctx.textAlign = "center";
      ctx.textBaseline = "bottom";
      ctx.fillText(fmt(g.median), cx, y - 10);
      ctx.fillStyle = t.muted;
      ctx.font = AXIS_FONT;
      ctx.textBaseline = "top";
      ctx.fillText(g.label, cx, plot.y1 + 8);
    });
  }

  function emptyState(ctx, w, h, t) {
    ctx.font = AXIS_FONT;
    ctx.fillStyle = t.muted;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("no measurements to plot", w / 2, h / 2);
  }

  window.MiniChart = { drawSpreadSeries, drawScatter, drawGroupedBars, fmt };
})();
