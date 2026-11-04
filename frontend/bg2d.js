// reascan 3D background - Canvas 2D, zero dependencies, one <canvas> for the page.
//
// Scene (token-colored, high depth, low text interference):
//   a. three soft nebula washes (cyan, magenta, violet) on long slow paths
//   b. a 3D starfield projected from a moving z-plane, with pointer parallax
//   c. a rotating wireframe globe: latitude + longitude rings on one stroke
//   d. a perspective floor grid converging on a horizon, drifting toward camera
//   e. a radial horizon bloom over the grid
// A destination-out centre pass then pushes the field back down where the form
// and the report are read. No additive blending: the light is alpha composited,
// so the light theme can use the same scene with darker tokens.
//
// Restraint rules: init after first paint (requestIdleCallback best-effort), DPR
// capped at 1.5, paused on visibilitychange, resize-aware, colors re-read from
// CSS tokens on every theme change via window.__reascanBG2D__setColors().
// Reduced motion or a missing 2D context leaves the canvas blank and hands over
// to a static CSS grid (style.css paints it from data-bg2d="css-fallback").
//
// The scene deliberately uses only ctx APIs available in the DOM shim used by
// bg2d.test.js: two stroke() calls per frame (globe + grid), fills for everything
// else, no gradients beyond createRadialGradient, no shadowBlur.

const DPR_CAP = 1.5;
const TAU = Math.PI * 2;
const STAR_COUNT_WIDE = 170;
const STAR_COUNT_NARROW = 90;
const STAR_ALPHA_STEPS = 6;
const LATITUDES = [-60, -30, 0, 30, 60];

const DEFAULTS = {
  line: 'rgba(92, 214, 255, 0.14)',
  glow: 'rgba(34, 211, 238, 0.10)',
  star: 'rgba(198, 246, 255, 0.90)',
  ring: 'rgba(255, 45, 149, 0.20)',
  horizon: 'rgba(34, 211, 238, 0.22)',
};

const TOKEN_MAP = {
  line: '--bg2d-line',
  glow: '--bg2d-glow',
  star: '--bg2d-star',
  ring: '--bg2d-ring',
  horizon: '--bg2d-horizon',
};

// "rgba(r,g,b,a)" -> "rgba(r,g,b,0)". The tokens are always rgba(); anything
// else fades to plain transparent rather than rendering a hard gradient edge.
function fadeToTransparent(color) {
  const m = String(color).match(/^rgba?\(([^)]+)\)$/i);
  if (!m) return 'rgba(0, 0, 0, 0)';
  const [r, g, b] = m[1].split(/[ ,/]+/).filter(Boolean);
  return `rgba(${r}, ${g}, ${b}, 0)`;
}

function readTokens() {
  const colors = { ...DEFAULTS };
  try {
    const cs = getComputedStyle(document.documentElement);
    for (const [key, prop] of Object.entries(TOKEN_MAP)) {
      const value = cs.getPropertyValue(prop).trim();
      if (value) colors[key] = value;
    }
  } catch { /* tokens unavailable: keep dark defaults */ }
  return colors;
}

export function startBG2D() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false;
  if (window.__reascanBG2D__started) return window.__reascanBG2D__status === 'running';
  window.__reascanBG2D__started = true;
  window.__reascanBG2D__status = 'starting';

  const canvas = document.getElementById('bg2d');
  if (!canvas) {
    window.__reascanBG2D__status = 'disabled';
    return false;
  }

  const mark = (value) => { try { document.documentElement.dataset.bg2d = value; } catch { /* noop */ } };

  let reduced = false;
  try {
    reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches === true;
  } catch { /* ambiguous support counts as reduced */ }
  if (reduced) {
    window.__reascanBG2D__status = 'css-fallback';
    mark('css-fallback');
    return false;
  }

  let ctx = null;
  try {
    ctx = canvas.getContext('2d');
  } catch { /* context creation can throw on broken setups */ }
  if (!ctx || typeof ctx.clearRect !== 'function') {
    window.__reascanBG2D__status = 'disabled';
    mark('disabled');
    return false;
  }

  const state = {
    colors: readTokens(),
    w: 0,
    h: 0,
    dpr: 0,
    stars: [],
    starBuckets: Array.from({ length: STAR_ALPHA_STEPS }, () => []),
    washes: [],
    horizonGlow: null,
    centre: null,
    globe: { cx: 0, cy: 0, r: 0, cosY: 1, sinY: 0, cosT: 1, sinT: 0 },
    t: 0,
    px: 0, py: 0,      // pointer offset, follows the grid and the globe
    tx: 0, ty: 0,      // pointer target
    running: false,
    dead: false,
    raf: 0,
    lastT: 0,
  };

  function wash(x, y, radius, color) {
    const g = ctx.createRadialGradient(0, 0, 0, 0, 0, radius);
    g.addColorStop(0, color);
    g.addColorStop(0.55, fadeToTransparent(color));
    g.addColorStop(1, fadeToTransparent(color));
    return { x, y, radius, g };
  }

  // Gradients bake their color stops, so they are built per resize / theme
  // change and only translated afterwards - one allocation, not one per frame.
  // The new set is built locally and swapped in at the end, so a throw halfway
  // through cannot leave the previous gradient set half-replaced.
  function buildGradients() {
    const { w, h } = state;
    const big = Math.max(w, h) * 0.8;
    const washes = [
      wash(0.18, 0.12, big, state.colors.glow),
      wash(0.84, 0.18, big * 0.86, state.colors.ring),
      wash(0.5, 1.03, big, state.colors.horizon),
    ];

    const horizonRadius = Math.max(w * 0.55, h * 0.34);
    const horizonGlow = ctx.createRadialGradient(
      w / 2, h * 0.61, 0,
      w / 2, h * 0.61, horizonRadius,
    );
    horizonGlow.addColorStop(0, state.colors.horizon);
    horizonGlow.addColorStop(1, fadeToTransparent(state.colors.horizon));

    const inner = Math.min(w, h) * 0.08;
    const outer = Math.min(w, h) * 0.46;
    const centre = ctx.createRadialGradient(w / 2, h / 2, inner, w / 2, h / 2, outer);
    centre.addColorStop(0, 'rgba(0, 0, 0, 0.48)');
    centre.addColorStop(1, 'rgba(0, 0, 0, 0)');

    state.washes = washes;
    state.horizonGlow = horizonGlow;
    state.centre = centre;
  }

  // Stars live in a normalized 3D box: x/y in roughly [-1.6, 1.6] x [-1.1, 1.1],
  // z in (0.08, 3.0]. Projection expands them from the centre as z decreases,
  // which reads as forward travel without any camera math.
  function seedStars() {
    const count = state.w < 640 ? STAR_COUNT_NARROW : STAR_COUNT_WIDE;
    state.stars = Array.from({ length: count }, () => ({
      x: (Math.random() * 2 - 1) * 1.6,
      y: (Math.random() * 2 - 1) * 1.1,
      z: 0.08 + Math.random() * 2.92,
      speed: 0.08 + Math.random() * 0.26,
      size: 0.55 + Math.random() * 1.5,
      alpha: 0.22 + Math.random() * 0.6,
    }));
  }

  function resize() {
    try {
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      const w = canvas.clientWidth || document.documentElement?.clientWidth || window.innerWidth || 0;
      const h = canvas.clientHeight || document.documentElement?.clientHeight || window.innerHeight || 0;
      if (w === state.w && h === state.h && dpr === state.dpr) return;
      state.dpr = dpr;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      // Draw in CSS pixels from here on, so the scene never needs the DPR.
      ctx.setTransform?.(dpr, 0, 0, dpr, 0, 0);
      state.w = w;
      state.h = h;
      buildGradients();
      const wanted = w < 640 ? STAR_COUNT_NARROW : STAR_COUNT_WIDE;
      if (state.stars.length !== wanted) seedStars();
    } catch { /* transient resize races: the next resize fixes it */ }
  }

  function drawWashes() {
    const { w, h } = state;
    for (let i = 0; i < state.washes.length; i += 1) {
      const wash = state.washes[i];
      ctx.save();
      ctx.translate(w * wash.x + state.px * 2.2, h * wash.y + state.py * 2.2);
      ctx.fillStyle = wash.g;
      ctx.fillRect(-wash.radius, -wash.radius, wash.radius * 2, wash.radius * 2);
      ctx.restore();
    }
  }

  // Stars are bucketed into six alpha bands before drawing, so 170 stars cost
  // six fill batches instead of 170 state flushes. Positions live on the star
  // objects (already allocated at seed time), not in per-frame tuples.
  function drawStars(dt) {
    const { w, h } = state;
    const cx = w / 2;
    const cy = h * 0.48;
    const focal = Math.min(w, h) * 1.05;
    const buckets = state.starBuckets;
    for (let i = 0; i < buckets.length; i += 1) buckets[i].length = 0;

    for (let i = 0; i < state.stars.length; i += 1) {
      const star = state.stars[i];
      star.z -= star.speed * dt;
      if (star.z <= 0.08) {
        star.z = 2.7 + Math.random() * 0.3;
        star.x = (Math.random() * 2 - 1) * 1.6;
        star.y = (Math.random() * 2 - 1) * 1.1;
      }
      const scale = focal / (star.z + 0.4);
      const sx = cx + star.x * scale * 0.22 + state.px * (1.2 / star.z);
      const sy = cy + star.y * scale * 0.22 + state.py * (1.2 / star.z);
      if (sx < -8 || sx > w + 8 || sy < -8 || sy > h + 8) continue;

      const depth = Math.max(0, Math.min(1, 1 - star.z / 3));
      const alpha = star.alpha * (0.18 + depth * 0.82);
      const bucket = Math.min(STAR_ALPHA_STEPS - 1, Math.floor(alpha * STAR_ALPHA_STEPS));
      star.sx = sx;
      star.sy = sy;
      star.sr = Math.max(0.35, star.size * (0.5 + depth * 0.9));
      buckets[bucket].push(star);
    }

    ctx.fillStyle = state.colors.star;
    for (let i = 0; i < buckets.length; i += 1) {
      const bucket = buckets[i];
      if (!bucket.length) continue;
      ctx.globalAlpha = (i + 0.5) / STAR_ALPHA_STEPS;
      ctx.beginPath();
      for (let j = 0; j < bucket.length; j += 1) {
        const star = bucket[j];
        ctx.moveTo(star.sx + star.sr, star.sy);
        ctx.arc(star.sx, star.sy, star.sr, 0, TAU);
      }
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  }

  // The globe projection reads its state from one mutable object, so the hot
  // frame path creates no closure or tuple per frame.
  function projectGlobe(x, y, z, move) {
    const g = state.globe;
    const xr = x * g.cosY - z * g.sinY;
    const zr = x * g.sinY + z * g.cosY;
    const yr = y * g.cosT - zr * g.sinT;
    const zt = y * g.sinT + zr * g.cosT;
    const persp = 1 / (1 + zt * 0.34);
    const sx = g.cx + xr * g.r * persp;
    const sy = g.cy + yr * g.r * persp;
    if (move) ctx.moveTo(sx, sy);
    else ctx.lineTo(sx, sy);
  }

  // Project a point on a unit sphere with simple rotations around Y then X.
  // The globe is one beginPath/stroke pass, matching the test's stroke budget.
  function drawGlobe() {
    const { w, h } = state;
    const g = state.globe;
    g.cx = w * 0.78 + state.px * 2.4;
    g.cy = h * 0.27 + state.py * 2;
    g.r = Math.min(w, h) * 0.16;
    const rotY = state.t * 0.14;
    const tilt = 0.42;
    g.cosY = Math.cos(rotY);
    g.sinY = Math.sin(rotY);
    g.cosT = Math.cos(tilt);
    g.sinT = Math.sin(tilt);

    ctx.beginPath();

    // latitude rings
    for (let l = 0; l < LATITUDES.length; l += 1) {
      const lat = (LATITUDES[l] * Math.PI) / 180;
      const ring = Math.cos(lat);
      const y = Math.sin(lat);
      for (let i = 0; i <= 48; i += 1) {
        const a = (i / 48) * TAU;
        projectGlobe(ring * Math.cos(a), y, ring * Math.sin(a), i === 0);
      }
    }

    // longitude rings
    for (let k = 0; k < 8; k += 1) {
      const lon = (k / 8) * TAU;
      const cosLon = Math.cos(lon);
      const sinLon = Math.sin(lon);
      for (let i = 0; i <= 32; i += 1) {
        const lat = -Math.PI / 2 + (i / 32) * Math.PI;
        const ring = Math.cos(lat);
        projectGlobe(ring * cosLon, Math.sin(lat), ring * sinLon, i === 0);
      }
    }

    ctx.strokeStyle = state.colors.ring;
    ctx.lineWidth = 1;
    ctx.globalAlpha = 0.72;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  function drawGrid() {
    const { w, h } = state;
    const horizon = h * 0.61 + state.py * 1.4;
    const cx = w / 2 + state.px * 8;
    const phase = (state.t * 0.16) % 1;

    ctx.beginPath();

    // Rays converging on the vanishing point; drawn a little past the edges so
    // the fan never shows a seam at the viewport border.
    for (let i = -11; i <= 11; i += 1) {
      const spread = i / 11;
      ctx.moveTo(cx + spread * w * 0.035, horizon);
      ctx.lineTo(cx + spread * w * 1.35, h + 2);
    }

    // Horizontal rungs with perspective spacing, drifting toward the camera.
    for (let i = 0; i < 20; i += 1) {
      const p = (i + phase) / 20;
      const y = horizon + Math.pow(p, 2.35) * (h - horizon);
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
    }

    // The horizon itself is part of the same path, so the whole floor is one
    // stroke call and the scene keeps a two-stroke frame budget.
    ctx.moveTo(0, horizon);
    ctx.lineTo(w, horizon);

    ctx.strokeStyle = state.colors.line;
    ctx.lineWidth = 1;
    ctx.globalAlpha = 0.85;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  function drawHorizon() {
    const { w, h } = state;
    // The bloom is painted across the whole viewport with a transparent falloff
    // and shifted with the pointer, so it cannot leave a hard horizontal seam
    // and cannot detach from the grid horizon under parallax.
    ctx.save();
    ctx.translate(state.px * 0.8, state.py * 0.8);
    ctx.fillStyle = state.horizonGlow;
    ctx.fillRect(0, 0, w, h);
    ctx.restore();
  }

  function softenCentre() {
    // Punches the middle of the field back toward the page background, which is
    // where the form, the verdict and the findings table are read. The glow
    // stays visible at the edges of the viewport.
    ctx.globalCompositeOperation = 'destination-out';
    ctx.fillStyle = state.centre;
    ctx.fillRect(0, 0, state.w, state.h);
    ctx.globalCompositeOperation = 'source-over';
  }

  function drawScene(dt) {
    if (!state.centre || !state.horizonGlow || state.washes.length === 0) return;
    ctx.clearRect(0, 0, state.w, state.h);
    drawWashes();
    drawStars(dt);
    drawGlobe();
    drawGrid();
    drawHorizon();
    softenCentre();
  }

  function loop(t) {
    if (state.dead) return;
    const dtMs = state.lastT ? t - state.lastT : 16;
    state.lastT = t;
    const delta = Math.min(Math.max(dtMs, 4), 50) / 1000; // clamp: tab-restore spikes
    state.t += delta;
    state.px += (state.tx - state.px) * 0.04;
    state.py += (state.ty - state.py) * 0.04;
    try {
      drawScene(delta);
    } catch {
      // A canvas that throws mid-frame would otherwise spin silently and leave a
      // blank hole; hand the page its static grid instead. This is terminal: a
      // later visibilitychange must not resurrect the broken loop, and the stale
      // frame is cleared so the CSS fallback is not composited over it.
      state.dead = true;
      try { ctx.clearRect(0, 0, state.w, state.h); } catch { /* ignore */ }
      teardown();
      mark('css-fallback');
      if (typeof window !== 'undefined') window.__reascanBG2D__status = 'css-fallback';
      return;
    }
    state.raf = state.running ? requestAnimationFrame(loop) : 0;
  }

  const onPointerMove = (e) => {
    state.tx = ((e.clientX / (window.innerWidth || 1)) - 0.5) * 20;
    state.ty = ((e.clientY / (window.innerHeight || 1)) - 0.5) * 20;
  };
  const onVisibility = () => {
    if (state.dead) return;
    state.running = !document.hidden;
    if (state.running && !state.raf) state.raf = requestAnimationFrame(loop);
  };
  function teardown() {
    state.running = false;
    if (state.raf && typeof cancelAnimationFrame === 'function') {
      try { cancelAnimationFrame(state.raf); } catch { /* ignore */ }
    }
    state.raf = 0;
  }

  let resizePending = 0;
  const onResize = () => {
    if (resizePending) return;
    const schedule = typeof requestAnimationFrame === 'function'
      ? requestAnimationFrame
      : (fn) => { fn(); return 0; };
    resizePending = schedule(() => {
      resizePending = 0;
      resize();
    });
  };

  window.addEventListener('resize', onResize, { passive: true });
  window.addEventListener('mousemove', onPointerMove, { passive: true });
  document.addEventListener('visibilitychange', onVisibility, { passive: true });
  window.addEventListener('beforeunload', teardown, { passive: true });

  // Theme switch: re-read the tokens and rebuild the gradients that bake them.
  window.__reascanBG2D__setColors = () => {
    if (state.dead) return;
    try {
      state.colors = readTokens();
      buildGradients();
    } catch { /* keep the last good palette */ }
  };

  // Lazy kick-off: first paint first, then idle work.
  resize();
  const kick = () => { if (!state.dead && !state.raf) onVisibility(); };
  if (typeof requestIdleCallback === 'function') requestIdleCallback(kick, { timeout: 1500 });
  else setTimeout(kick, 120);
  window.__reascanBG2D__status = 'running';
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
