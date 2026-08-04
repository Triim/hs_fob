"use strict";
/*
 * Presentation shell: client-side tab switching only.
 *
 * This file is deliberately independent of app.js (the live-demo logic + signing).
 * It never touches demo state — it only shows/hides top-level <section.tab-panel>
 * elements when a tab in <nav.tabs> is clicked. "Live demo" is active by default
 * from the markup, so the demo's load-time behavior (self-test, WS connect) is
 * unchanged.
 */
(function () {
  function structureStorySlides() {
    document.querySelectorAll(".story-screen").forEach((screen) => {
      if (screen.querySelector(":scope > .story-copy")) return;

      const copy = document.createElement("div");
      copy.className = "story-copy";
      const material = document.createElement("div");
      material.className = "story-material";

      Array.from(screen.children).forEach((node) => {
        const isCopy = node.matches(".deck-eyebrow, .deck-title, .deck-lead")
          || (screen.classList.contains("story-intro") && node.matches(".story-author"));
        (isCopy ? copy : material).appendChild(node);
      });
      screen.append(copy, material);
    });
  }

  function activate(name) {
    document.querySelectorAll(".tab-btn").forEach((b) => {
      const on = b.dataset.tab === name;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      const on = p.dataset.tab === name;
      p.classList.toggle("active", on);
      // Reset a content deck to its first screen each time it's shown.
      // Force an instant jump (not the deck's smooth scroll) so the reset
      // is immediate rather than animating from wherever it was left.
      if (on) {
        const prev = p.style.scrollBehavior;
        p.style.scrollBehavior = "auto";
        p.scrollTop = 0;
        p.style.scrollBehavior = prev;
      }
    });
  }

  function wireTabs() {
    const nav = document.querySelector("nav.tabs");
    if (!nav) return;
    nav.addEventListener("click", (e) => {
      const btn = e.target.closest(".tab-btn");
      if (btn) activate(btn.dataset.tab);
    });
    // Left/right arrow navigation between tabs.
    nav.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const btns = Array.from(nav.querySelectorAll(".tab-btn"));
      const i = btns.findIndex((b) => b.classList.contains("active"));
      if (i < 0) return;
      const next = e.key === "ArrowRight" ? (i + 1) % btns.length : (i - 1 + btns.length) % btns.length;
      activate(btns[next].dataset.tab);
      btns[next].focus();
      e.preventDefault();
    });
  }

  function init() {
    structureStorySlides();
    wireTabs();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
