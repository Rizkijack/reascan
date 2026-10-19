// reascan theme - light/dark/system, segmented toggle in the header.
//
// The data-theme attribute is set pre-paint by the inline head script in
// index.html (anti-flash). This module owns everything after that: the toggle
// buttons, persistence under "reascan:theme", and the live follow of
// prefers-color-scheme while system mode is active. It loads as its own module
// script, so it must never crash the page: every storage/media-query access is
// guarded, and a hard failure at worst leaves the inline bootstrap's choice in
// place.

const MODE_KEY = 'reascan:theme';
const MODES = ['light', 'dark', 'system'];

let currentMode = 'dark';
let cleaned = false;

function storedMode() {
  try {
    const raw = localStorage.getItem(MODE_KEY);
    return MODES.includes(raw) ? raw : null;
  } catch {
    return null; // private browsing / storage denied - default wins
  }
}

// Resolves any mode to the concrete theme painted on <html>. "Unknown" and
// "system" fall through to the OS preference; "light" and "dark" are explicit
// choices and must ignore it entirely - otherwise explicit Dark flips to light
// on an OS set to light. A missing matchMedia reads as dark, which keeps the
// module usable in minimal DOM shims.
function resolveTheme(mode) {
  if (mode === 'light') return 'light';
  if (mode === 'dark') return 'dark';
  const mq = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-color-scheme: light)')
    : null;
  return mq?.matches === true ? 'light' : 'dark';
}

export function getTheme() {
  return document.documentElement?.dataset?.theme ?? 'dark';
}

export function getMode() {
  return currentMode;
}

// mode: light | dark | system. persist=false for the boot-time application, so
// a first visit stays unstored until the user actually chooses.
export function applyTheme(mode, { persist = true } = {}) {
  currentMode = MODES.includes(mode) ? mode : 'dark';
  const theme = resolveTheme(currentMode);
  try {
    document.documentElement.dataset.theme = theme;
  } catch { /* no documentElement: nothing to paint */ }
  if (persist) {
    try {
      if (currentMode === 'dark') localStorage.removeItem(MODE_KEY); // dark is the default
      else localStorage.setItem(MODE_KEY, currentMode);
    } catch { /* storage denied */ }
  }
  // The WebGL background reads its colors from the live tokens; ask it to re-read.
  try {
    window.__reascanBG2D__setColors?.();
  } catch { /* background module absent or broken: it is decorative */ }
  return theme;
}

// Follows the OS preference live, but only while system mode is selected.
function wireSystemPreference() {
  if (cleaned || typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
  let mq;
  try {
    mq = window.matchMedia('(prefers-color-scheme: light)');
  } catch {
    return;
  }
  const onChange = () => {
    if (currentMode === 'system') applyTheme('system', { persist: false });
  };
  try {
    mq.addEventListener('change', onChange);
  } catch {
    try { mq.addListener?.(onChange); } catch { /* very old engines: no live follow */ }
  }
}

export function initTheme(root = document) {
  if (typeof document === 'undefined') return;

  try {
    applyTheme(storedMode() ?? 'dark', { persist: false });
    const group = document.getElementById('theme-toggle');
    if (!group || typeof group.querySelectorAll !== 'function') return;
    const buttons = [...group.querySelectorAll('button[data-mode]')];
    const paint = () => {
      for (const b of buttons) {
        const active = b.dataset.mode === currentMode;
        b.classList?.toggle?.('is-active', active);
        b.setAttribute?.('aria-pressed', String(active));
      }
    };
    for (const b of buttons) {
      b.addEventListener('click', () => {
        applyTheme(b.dataset.mode ?? 'system');
        paint();
      });
    }
    paint();
    wireSystemPreference();
  } catch {
    // A headless or partial DOM (extension shims, readers) must not break the
    // page over a cosmetic control; the head script's theme stays in force.
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      try { initTheme(); } catch { /* decorative: never block the page */ }
    }, { once: true });
  } else {
    try { initTheme(); } catch { /* decorative: never block the page */ }
  }
}
