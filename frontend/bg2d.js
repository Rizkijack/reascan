// reascan 2D background - Canvas 2D, zero dependencies, one <canvas> for the page.
//
// Scene (all monochrome, token-colored, low contrast so text always wins):
//   a. a fine grid at two drift speeds, the slower layer fainter
//   b. two very soft radial washes on long, slow paths
//   c. ~60 motes rising slowly, thinned out on narrow viewports
// A radial pass then softens the middle of the field, where the form and the
// report live. The pointer nudges the grid offset and the wash centres by a few
// pixels, lerped inside the same RAF loop.
//
// No blend-mode trickery: the washes are low-alpha alpha compositing, not
// additive glow. Additive would blow out to white in the light theme, and a
// glow is not the language this page speaks anyway.
//
// Restraint rules: init after first paint (requestIdleCallback best-effort), DPR
// capped at 1.5, paused on visibilitychange, resize-aware, colors re-read from
// CSS tokens on every theme change via window.__reascanBG2D__setColors().
// Reduced motion or a missing 2D context leaves the canvas blank and hands over
// to a static CSS grid (style.css paints it from data-bg2d="css-fallback").

const DPR_CAP = 1.5;
const CELL = 64; // matches the CSS fallback grid, so both read as one system
const MOTE_COUNT_WIDE = 60;
const MOTE_COUNT_NARROW = 28;
const TAU = Math.PI * 2;

// "rgba(r,g,b,a)" -> "rgba(r,g,b,0)". The tokens are always rgba(); anything
// else fades to plain transparent rather than rendering a hard gradient edge.
function fadeToTransparent(color) {
  const m = String(color).match(/^rgba?\(([^)]+)\)$/i);
  if (!m) return 'rgba(0, 0, 0, 0)';
  const [r, g, b] = m[1].split(/[ ,/]+/).filter(Boolean);
  return `rgba(${r}, ${g}, ${b}, 0)`;
}

function readTokens() {
  let line = 'rgba(255, 255, 255, 0.06)';
  let glow = 'rgba(74, 159, 255, 0.10)';
  try {
    const cs = getComputedStyle(document.documentElement);
    line = cs.getPropertyValue('--bg2d-line').trim() || line;
    glow = cs.getPropertyValue('--bg2d-glow').trim() || glow;
  } catch { /* tokens unavailable: keep dark defaults */ }
  return { line, glow };
}

export function startBG2D() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false;
  if (window.__reascanBG2D__started) return true; // idempotent mount
  window.__reascanBG2D__started = true;

  const canvas = document.getElementById('bg2d');
  if (!canvas) return false;

  const mark = (value) => { try { document.documentElement.dataset.bg2d = value; } catch { /* noop */ } };

  let reduced = false;
  try {
    reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches === true;
  } catch { /* ambiguous support counts as reduced */ }
  if (reduced) { mark('css-fallback'); return false; }

  let ctx = null;
  try {
    ctx = canvas.getContext('2d');
  } catch { /* context creation can throw on broken setups */ }
  if (!ctx || typeof ctx.clearRect !== 'function') { mark('disabled'); return false; }

  const state = {
    colors: readTokens(),
    w: 0, h: 0,
    motes: [],
    t: 0,
    px: 0, py: 0,      // grid offset, follows the pointer
    tx: 0, ty: 0,      // pointer target
    running: false,
    raf: 0,
    lastT: 0,
    washes: [],
    centre: null,
  };

  // Gradients bake their color stops, so they are built per resize / theme
  // change and only translated afterwards - one allocation, not one per frame.
  function buildGradients() {
    const { w, h } = state;
    const big = Math.max(w, h) * 0.75;
    state.washes = [
      { fx: 0.26, fy: 0.20, drift: 2.4, r: big, g: ctx.createRadialGradient(0, 0, 0, 0, 0, big) },
      { fx: 0.78, fy: 0.76, drift: -3.1, r: big * 0.9, g: ctx.createRadialGradient(0, 0, 0, 0, 0, big * 0.9) },
    ];
    for (const wash of state.washes) {
      wash.g.addColorStop(0, state.colors.glow);
      wash.g.addColorStop(1, fadeToTransparent(state.colors.glow));
    }
    const inner = Math.min(w, h) * 0.10;
    const outer = Math.min(w, h) * 0.62;
    state.centre = ctx.createRadialGradient(w / 2, h / 2, inner, w / 2, h / 2, outer);
    state.centre.addColorStop(0, 'rgba(0, 0, 0, 0.72)');
    state.centre.addColorStop(1, 'rgba(0, 0, 0, 0)');
  }

  function seedMotes() {
    const count = state.w < 640 ? MOTE_COUNT_NARROW : MOTE_COUNT_WIDE;
    state.motes = Array.from({ length: count }, () => ({
      x: Math.random() * state.w,
      y: Math.random() * state.h,
      r: 0.6 + Math.random() * 1.1,
      vx: (Math.random() - 0.5) * 6,
      vy: -3 - Math.random() * 7,
      a: 0.25 + Math.random() * 0.45,
    }));
  }

  function resize() {
    try {
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      const w = window.innerWidth || 0;
      const h = window.innerHeight || 0;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      // Draw in CSS pixels from here on, so the scene never needs the DPR.
      ctx.setTransform?.(dpr, 0, 0, dpr, 0, 0);
      state.w = w;
      state.h = h;
      buildGradients();
      if (!state.motes.length) seedMotes();
    } catch { /* transient resize races: the next resize fixes it */ }
  }

  function drawWashes() {
    const { w, h } = state;
    for (const wash of state.washes) {
      ctx.save();
      ctx.translate(w * wash.fx + state.px * wash.drift, h * wash.fy + state.py * wash.drift);
      ctx.fillStyle = wash.g;
      ctx.fillRect(-wash.r, -wash.r, wash.r * 2, wash.r * 2);
      ctx.restore();
    }
  }

  function drawGridLayer(distance, alpha) {
    const { w, h } = state;
    ctx.beginPath();
    for (let x = ((distance % CELL) + CELL) % CELL; x < w; x += CELL) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
    for (let y = ((distance % CELL) + CELL) % CELL; y < h; y += CELL) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.globalAlpha = alpha;
    ctx.strokeStyle = state.colors.line;
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  function drawMotes(dt) {
    const { w, h } = state;
    ctx.fillStyle = state.colors.glow;
    for (const mote of state.motes) {
      mote.x += mote.vx * dt;
      mote.y += mote.vy * dt;
      if (mote.y < -4) { mote.y = h + 4; mote.x = Math.random() * w; }
      if (mote.x < -4) mote.x = w + 4;
      else if (mote.x > w + 4) mote.x = -4;
      ctx.globalAlpha = mote.a;
      ctx.beginPath();
      ctx.arc(mote.x, mote.y, mote.r, 0, TAU);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  }

  function softenCentre() {
    // Punches the middle of the field back toward the page background, which is
    // where the form, the verdict and the findings table are read.
    ctx.globalCompositeOperation = 'destination-out';
    ctx.fillStyle = state.centre;
    ctx.fillRect(0, 0, state.w, state.h);
    ctx.globalCompositeOperation = 'source-over';
  }

  function drawScene(dt) {
    ctx.clearRect(0, 0, state.w, state.h);
    drawWashes();
    drawGridLayer(state.t * 3.2, 1);
    drawGridLayer(state.t * 1.7, 0.5);
    drawMotes(dt);
    softenCentre();
  }

  function loop(t) {
    const dtMs = state.lastT ? t - state.lastT : 16;
    state.lastT = t;
    const delta = Math.min(Math.max(dtMs, 4), 50) / 1000; // clamp: tab-restore spikes
    state.t += delta;
    state.px += (state.tx - state.px) * 0.045;
    state.py += (state.ty - state.py) * 0.045;
    try {
      drawScene(delta);
    } catch {
      // A canvas that throws mid-frame would otherwise spin silently and leave a
      // blank hole; hand the page its static grid instead.
      teardown();
      mark('css-fallback');
      return;
    }
    state.raf = state.running ? requestAnimationFrame(loop) : 0;
  }

  const onPointerMove = (e) => {
    state.tx = ((e.clientX / (window.innerWidth || 1)) - 0.5) * 20;
    state.ty = ((e.clientY / (window.innerHeight || 1)) - 0.5) * 20;
  };
  const onVisibility = () => {
    state.running = !document.hidden;
    if (state.running && !state.raf) state.raf = requestAnimationFrame(loop);
  };
  function teardown() {
    state.running = false;
    if (state.raf) cancelAnimationFrame(state.raf);
    state.raf = 0;
  }

  window.addEventListener('resize', resize, { passive: true });
  window.addEventListener('mousemove', onPointerMove, { passive: true });
  document.addEventListener('visibilitychange', onVisibility, { passive: true });
  window.addEventListener('beforeunload', teardown, { passive: true });

  // Theme switch: re-read the tokens and rebuild the gradients that bake them.
  window.__reascanBG2D__setColors = () => {
    try {
      state.colors = readTokens();
      buildGradients();
    } catch { /* keep the last good palette */ }
  };

  // Lazy kick-off: first paint first, then idle work.
  resize();
  const kick = () => { if (!state.raf) onVisibility(); };
  if (typeof requestIdleCallback === 'function') requestIdleCallback(kick, { timeout: 1500 });
  else setTimeout(kick, 120);
  return true;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const boot = () => {
    try {
      startBG2D();
    } catch {
      try { document.documentElement.dataset.bg2d = 'disabled'; } catch { /* noop */ }
    }
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
  else boot();
}