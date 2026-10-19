// reascan 3D background - raw WebGL, zero dependencies, one <canvas> for the page.
//
// Scene (all monochrome, token-colored, low contrast so text always wins):
//   a. two wireframe grid planes drifting (motion = matrix translate + wrap)
//   b. ~120 drifting particles (POINTS)
//   c. two wireframe icosahedra rotating at different phases
// Layers move at different speeds so the field reads as depth; pointer parallax
// lerps a ±3deg world tilt inside the same RAF loop.
//
// Restraint rules: init after first paint (requestIdleCallback best-effort), DPR
// capped at 1.5, paused on visibilitychange, resize-aware, colors re-read from
// CSS tokens on every theme change via window.__reascanBG3D__setColors().
// Reduced motion or missing WebGL leaves the canvas blank and hands over to a
// static CSS grid (style.css paints it from data-bg3d="css-fallback").

const DPR_CAP = 1.5;
const PARTICLE_COUNT = 120;

// Canonical icosahedron, normalized to unit length; edges derived from the 5
// nearest neighbours (hardcoded primitive, no math library).
const ICO_T = (1 + Math.sqrt(5)) / 2;
const ICO_VERTICES = [[-1, ICO_T, 0], [1, ICO_T, 0], [-1, -ICO_T, 0], [1, -ICO_T, 0],
  [0, -1, ICO_T], [0, 1, ICO_T], [0, -1, -ICO_T], [0, 1, -ICO_T],
  [ICO_T, 0, -1], [ICO_T, 0, 1], [-ICO_T, 0, -1], [-ICO_T, 0, 1]]
  .map(([x, y, z]) => {
    const len = Math.hypot(x, y, z);
    return [x / len, y / len, z / len];
  });
const ICO_EDGES = (() => {
  const pairs = new Set();
  for (let a = 0; a < 12; a++) {
    const dists = [];
    for (let b = 0; b < 12; b++) {
      if (a === b) continue;
      const [ax, ay, az] = ICO_VERTICES[a];
      const [bx, by, bz] = ICO_VERTICES[b];
      dists.push([(ax - bx) ** 2 + (ay - by) ** 2 + (az - bz) ** 2, b]);
    }
    dists.sort((p, q) => p[0] - q[0]);
    for (const [, b] of dists.slice(0, 5)) pairs.add(`${Math.min(a, b)},${Math.max(a, b)}`);
  }
  return [...pairs].map((k) => k.split(',').map(Number));
})();

// --- tiny mat4 helpers (column-major, WebGL convention) ---------------------

function mat4Multiply(a, b) {
  const out = new Array(16).fill(0);
  for (let col = 0; col < 4; col++) {
    for (let row = 0; row < 4; row++) {
      let sum = 0;
      for (let k = 0; k < 4; k++) sum += a[k * 4 + row] * b[col * 4 + k];
      out[col * 4 + row] = sum;
    }
  }
  return out;
}

const mat4Translate = (x, y, z) => [
  1, 0, 0, 0,
  0, 1, 0, 0,
  0, 0, 1, 0,
  x, y, z, 1,
];

const mat4Scale = (s) => [
  s, 0, 0, 0,
  0, s, 0, 0,
  0, 0, s, 0,
  0, 0, 0, 1,
];

function mat4RotateX(r) {
  const c = Math.cos(r), s = Math.sin(r);
  return [
    1, 0, 0, 0,
    0, c, s, 0,
    0, -s, c, 0,
    0, 0, 0, 1,
  ];
}

function mat4RotateY(r) {
  const c = Math.cos(r), s = Math.sin(r);
  return [
    c, 0, s, 0,
    0, 1, 0, 0,
    -s, 0, c, 0,
    0, 0, 0, 1,
  ];
}

function mat4Perspective(fov, aspect, near, far) {
  const f = 1 / Math.tan(fov / 2);
  const nf = 1 / (near - far);
  return [
    f / aspect, 0, 0, 0,
    0, f, 0, 0,
    0, 0, (far + near) * nf, -1,
    0, 0, 2 * far * near * nf, 0,
  ];
}

// Parse "rgba(…)" / "#rgba" from computed token values into a 4-float color.
function parseColor(value, fallback) {
  if (typeof value !== 'string') return fallback;
  const m = value.match(/rgba?\(([^)]+)\)/);
  if (m) {
    const parts = m[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    return [
      (parts[0] ?? 255) / 255,
      (parts[1] ?? 255) / 255,
      (parts[2] ?? 255) / 255,
      parts.length > 3 ? parts[3] : 0.06,
    ];
  }
  const hex = value.match(/^#([0-9a-f]{3,8})$/i);
  if (hex) {
    const h = hex[1];
    const full = h.length <= 4 ? [...h].map((c) => c + c).join('') : h;
    return [
      parseInt(full.slice(0, 2), 16) / 255,
      parseInt(full.slice(2, 4), 16) / 255,
      parseInt(full.slice(4, 6), 16) / 255,
      full.length >= 8 ? parseInt(full.slice(6, 8), 16) / 255 : 0.06,
    ];
  }
  return fallback;
}

function readTokenColors() {
  let line = [1, 1, 1, 0.06];
  let accent = [0.29, 0.62, 1, 0.05];
  try {
    const cs = getComputedStyle(document.documentElement);
    line = parseColor(cs.getPropertyValue('--bg3d-line'), line);
    accent = parseColor(cs.getPropertyValue('--bg3d-accent'), accent);
  } catch { /* tokens unavailable: keep dark defaults */ }
  return { line, accent };
}

export function startBG3D() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false;
  if (window.__reascanBG3D__started) return true; // idempotent mount
  window.__reascanBG3D__started = true;

  const canvas = document.getElementById('bg3d');
  if (!canvas) return false;

  const mark = (value) => { try { document.documentElement.dataset.bg3d = value; } catch { /* noop */ } };

  let reduced = false;
  try {
    reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches === true;
  } catch { /* ambiguous support counts as reduced */ }
  if (reduced) { mark('css-fallback'); return false; }

  let gl = null;
  try {
    gl = canvas.getContext('webgl', { antialias: true, alpha: true })
      ?? canvas.getContext('experimental-webgl', { antialias: true, alpha: true });
  } catch { /* context creation can throw on broken setups */ }
  if (!gl) { mark('disabled'); return false; }

  const state = {
    colors: readTokenColors(),
    particles: buildParticles(),
    scroll: 0,
    spin: 0,
    tiltX: 0, tiltY: 0,
    targetTiltX: 0, targetTiltY: 0,
    running: false,
    raf: 0,
    lastT: 0,
  };

  let program = null;
  try {
    program = buildProgram(gl);
  } catch {
    program = null;
  }
  if (!program) { mark('disabled'); return false; }

  gl.useProgram(program);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

  const uMVP = gl.getUniformLocation(program, 'uMVP');
  const uColor = gl.getUniformLocation(program, 'uColor');
  const uPointSize = gl.getUniformLocation(program, 'uPointSize');
  const aPos = gl.getAttribLocation(program, 'aPos');
  gl.enableVertexAttribArray(aPos);

  const gridVerts = makeGridVertices();
  const particles = state.particles;
  const particleVerts = new Float32Array(particles.map((p) => [p[0], p[1], p[2]]).flat());
  const icoVerts = (() => {
    const flat = [];
    for (const [a, b] of ICO_EDGES) flat.push(...ICO_VERTICES[a], ...ICO_VERTICES[b]);
    return new Float32Array(flat);
  })();

  const buffers = {
    grid: makeBuffer(gridVerts),
    particles: makeBuffer(particleVerts),
    ico: makeBuffer(icoVerts),
  };

  function makeBuffer(data) {
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    return buf;
  }

  function compile(glx, type, src) {
    const sh = glx.createShader(type);
    glx.shaderSource(sh, src);
    glx.compileShader(sh);
    if (!glx.getShaderParameter(sh, glx.COMPILE_STATUS)) throw new Error('shader compile failed');
    return sh;
  }

  function buildProgram(glx) {
    const vs = compile(glx, glx.VERTEX_SHADER, `
      attribute vec3 aPos;
      uniform mat4 uMVP;
      uniform float uPointSize;
      void main() {
        gl_Position = uMVP * vec4(aPos, 1.0);
        gl_PointSize = uPointSize;
      }
    `);
    const fs = compile(glx, glx.FRAGMENT_SHADER, `
      precision mediump float;
      uniform vec4 uColor;
      void main() { gl_FragColor = uColor; }
    `);
    const p = glx.createProgram();
    glx.attachShader(p, vs);
    glx.attachShader(p, fs);
    glx.linkProgram(p);
    if (!glx.getProgramParameter(p, glx.LINK_STATUS)) throw new Error('program link failed');
    return p;
  }

  function resize() {
    try {
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      canvas.width = Math.max(1, Math.floor(window.innerWidth * dpr));
      canvas.height = Math.max(1, Math.floor(window.innerHeight * dpr));
      gl.viewport(0, 0, canvas.width, canvas.height);
    } catch { /* transient resize races: the next resize fixes it */ }
  }

  function bindBuffer(buf) {
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.vertexAttribPointer(aPos, 3, gl.FLOAT, false, 0, 0);
  }

  function drawGrid(base, height, offset, color, alphaScale) {
    const mvp = mat4Multiply(base, mat4Translate(0, height, offset));
    gl.uniformMatrix4fv(uMVP, false, new Float32Array(mvp));
    gl.uniform4f(uColor, color[0], color[1], color[2], color[3] * alphaScale);
    gl.uniform1f(uPointSize, 1);
    bindBuffer(buffers.grid);
    gl.drawArrays(gl.LINES, 0, gridVerts.length / 3);
  }

  function drawParticles(base, delta) {
    const data = particleVerts;
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p[0] += p[3] * delta;
      p[1] += p[4] * delta;
      p[2] += p[5] * delta;
      if (p[0] > 25 || p[0] < -25) { p[0] = Math.max(-25, Math.min(25, p[0])); p[3] *= -1; }
      if (p[1] > 11 || p[1] < -3) { p[1] = Math.max(-3, Math.min(11, p[1])); p[4] *= -1; }
      if (p[2] > 25 || p[2] < -25) { p[2] = Math.max(-25, Math.min(25, p[2])); p[5] *= -1; }
      data[i * 3] = p[0];
      data[i * 3 + 1] = p[1];
      data[i * 3 + 2] = p[2];
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.particles);
    gl.bufferSubData(gl.ARRAY_BUFFER, 0, data);
    gl.vertexAttribPointer(aPos, 3, gl.FLOAT, false, 0, 0);
    gl.uniformMatrix4fv(uMVP, false, new Float32Array(base));
    gl.uniform4f(uColor, state.colors.line[0], state.colors.line[1], state.colors.line[2], Math.min(1, state.colors.line[3] * 6));
    gl.uniform1f(uPointSize, 2);
    gl.drawArrays(gl.POINTS, 0, particles.length);
  }

  function drawIco(base, x, y, z, phase, scale) {
    const model = mat4Multiply(
      mat4Translate(x, y, z),
      mat4Multiply(mat4RotateY(phase), mat4Multiply(mat4RotateX(phase * 0.7), mat4Scale(scale))),
    );
    const mvp = mat4Multiply(base, model);
    gl.uniformMatrix4fv(uMVP, false, new Float32Array(mvp));
    const c = state.colors.accent;
    gl.uniform4f(uColor, c[0], c[1], c[2], Math.min(0.35, c[3] * 4));
    gl.uniform1f(uPointSize, 1);
    bindBuffer(buffers.ico);
    gl.drawArrays(gl.LINES, 0, icoVerts.length / 3);
  }

  function drawScene(delta) {
    gl.clearColor(0, 0, 0, 0); // canvas stays transparent; the page bg shows through
    gl.clear(gl.COLOR_BUFFER_BIT);

    const aspect = canvas.width / Math.max(1, canvas.height);
    const proj = mat4Perspective(Math.PI / 5, aspect, 0.1, 160);
    const view = mat4Multiply(mat4RotateX(-0.4 + state.tiltX), mat4Translate(0, -3.5, -14));
    const world = mat4Multiply(view, mat4RotateY(state.tiltY));
    const base = mat4Multiply(proj, world);

    const GRID_STEP = 3;
    const wrap = state.scroll % GRID_STEP;
    drawGrid(base, 0, wrap, state.colors.line, 1);            // near plane, faster scroll
    drawGrid(base, 5, -(wrap * 0.5), state.colors.line, 0.5); // far plane, slower + fainter

    drawParticles(base, delta);

    drawIco(base, -10, 5, -34, state.spin * 0.8, 2.4);
    drawIco(base, 12, -1, -48, state.spin * 0.5 + 2, 3.6);
  }

  function loop(t) {
    const dtMs = state.lastT ? t - state.lastT : 16;
    state.lastT = t;
    const delta = Math.min(Math.max(dtMs, 4), 50) / 1000; // clamp: tab-restore spikes
    state.scroll += delta * 1.4;
    state.spin += delta * 0.25;
    state.tiltX += (state.targetTiltX - state.tiltX) * 0.05;
    state.tiltY += (state.targetTiltY - state.tiltY) * 0.05;
    try {
      drawScene(delta);
    } catch {
      state.running = false; // GL context lost or driver hiccup: stop quietly
    }
    state.raf = state.running ? requestAnimationFrame(loop) : 0;
  }

  function buildParticles() {
    const seed = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      seed.push([
        (Math.random() - 0.5) * 50,
        (Math.random() - 0.5) * 14,
        (Math.random() - 0.5) * 50,
        (Math.random() - 0.5) * 0.02, // drift vx
        (Math.random() - 0.5) * 0.02, // drift vy
        (Math.random() - 0.5) * 0.02, // drift vz
      ]);
    }
    return seed;
  }

  function makeGridVertices() {
    // 60x60 plane, 3-step cells: horizontal + vertical strips on the XZ plane.
    const S = 60, STEP = 3, HALF = S / 2;
    const lines = [];
    for (let i = -HALF; i <= HALF; i += STEP) {
      lines.push(-HALF, 0, i, HALF, 0, i); // along X
      lines.push(i, 0, -HALF, i, 0, HALF); // along Z
    }
    return new Float32Array(lines);
  }

  const onResize = () => resize();
  const onPointerMove = (e) => {
    // ≈ ±3deg around center
    state.targetTiltY = ((e.clientX / window.innerWidth) - 0.5) * (Math.PI / 30);
    state.targetTiltX = ((e.clientY / window.innerHeight) - 0.5) * (Math.PI / 30);
  };
  const onVisibility = () => {
    state.running = !document.hidden;
    if (state.running && !state.raf) state.raf = requestAnimationFrame(loop);
  };
  const teardown = () => {
    state.running = false;
    if (state.raf) cancelAnimationFrame(state.raf);
    state.raf = 0;
  };

  window.addEventListener('resize', onResize, { passive: true });
  window.addEventListener('mousemove', onPointerMove, { passive: true });
  document.addEventListener('visibilitychange', onVisibility, { passive: true });
  window.addEventListener('beforeunload', teardown, { passive: true });
  // A lost GL context would keep the RAF loop drawing into nothing and never
  // reach the static-grid fallback, so treat it like the no-WebGL case.
  canvas.addEventListener('webglcontextlost', (e) => {
    e.preventDefault();
    teardown();
    document.documentElement.dataset.bg3d = 'css-fallback';
  });

  // Update the palette on theme change without touching the GL pipeline.
  window.__reascanBG3D__setColors = () => {
    try { state.colors = readTokenColors(); } catch { /* keep the last good palette */ }
  };

  // Lazy kick-off: first paint first, then idle work.
  resize();
  const kick = () => { if (!state.raf) onVisibility(); };
  if (typeof requestIdleCallback === 'function') requestIdleCallback(kick, { timeout: 1500 });
  else setTimeout(kick, 120);
  return true;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      try {
        startBG3D();
      } catch {
        try { document.documentElement.dataset.bg3d = 'disabled'; } catch { /* noop */ }
      }
    }, { once: true });
  } else {
    try {
      startBG3D();
    } catch {
      try { document.documentElement.dataset.bg3d = 'disabled'; } catch { /* noop */ }
    }
  }
}
