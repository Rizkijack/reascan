import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, createDocument } from './dom-shim.js';

// bg3d.js contract, WITHOUT any real Chrome/WebGL: reduced motion -> CSS grid
// handoff (data-bg3d="css-fallback"), no/ throwing GL -> "disabled", startup is
// idempotent, the backing pixel ratio is capped at 1.5, and the RAF loop pauses
// on visibilitychange instead of rendering into a hidden tab.

const mod = () => import('../bg3d.js');

// A GL stub that compiles, links, and accepts every draw call. The scene shape
// is out of scope here - the fallback/beam wiring is what is pinned.
function mockGL() {
  return {
    BLEND: 1, SRC_ALPHA: 2, ONE_MINUS_SRC_ALPHA: 3, FLOAT: 4, ARRAY_BUFFER: 5,
    STATIC_DRAW: 6, LINES: 7, POINTS: 8, VERTEX_SHADER: 9, FRAGMENT_SHADER: 10,
    COMPILE_STATUS: 11, LINK_STATUS: 12, COLOR_BUFFER_BIT: 13,
    useProgram() {}, enable() {}, blendFunc() {},
    getUniformLocation() { return {}; }, getAttribLocation() { return 0; },
    enableVertexAttribArray() {},
    createBuffer() { return {}; }, bindBuffer() {}, bufferData() {}, bufferSubData() {},
    createShader() { return {}; }, shaderSource() {}, compileShader() {},
    getShaderParameter() { return true; },
    createProgram() { return {}; }, attachShader() {}, linkProgram() {},
    getProgramParameter() { return true; },
    viewport() {}, drawArrays() {}, clear() {}, clearColor() {},
    uniform1f() {}, uniform4f() {}, uniformMatrix4fv() {}, vertexAttribPointer() {},
  };
}

function env({ dpr = 1, reduced = false, gl = null, contextThrows = false, withCanvas = true } = {}) {
  const canvas = new El('canvas');
  const getContextCalls = [];
  canvas.getContext = (type) => {
    getContextCalls.push(type);
    if (contextThrows) throw new Error('broken driver');
    return gl;
  };
  const ids = withCanvas ? { bg3d: canvas } : {};
  const docEl = new El('html');
  const doc = createDocument({ ids, documentElement: docEl });
  const matchMedia = (q) => ({ matches: reduced && q.includes('prefers-reduced-motion'), addEventListener() {} });
  const win = {
    matchMedia,
    devicePixelRatio: dpr,
    innerWidth: 200,
    innerHeight: 100,
    addEventListener() {},
    addEventListenerCalls: [],
  };
  win.addEventListener = (type) => { win.addEventListenerCalls.push(type); };
  const rafQueue = [];
  const idleCbs = [];
  const real = {
    document: globalThis.document,
    window: globalThis.window,
    localStorage: globalThis.localStorage,
    getComputedStyle: globalThis.getComputedStyle,
    requestAnimationFrame: globalThis.requestAnimationFrame,
    requestIdleCallback: globalThis.requestIdleCallback,
    setTimeout: globalThis.setTimeout,
  };
  globalThis.document = doc;
  globalThis.window = win;
  globalThis.getComputedStyle = () => ({ getPropertyValue: () => '' });
  globalThis.requestAnimationFrame = (cb) => { rafQueue.push(cb); return rafQueue.length; };
  globalThis.requestIdleCallback = (cb) => { idleCbs.push(cb); return idleCbs.length; };
  globalThis.setTimeout = () => { throw new Error('setTimeout must not be reached when requestIdleCallback exists'); };
  return {
    doc, win, canvas, docEl, getContextCalls, rafQueue, idleCbs,
    cleanup() {
      globalThis.document = real.document;
      globalThis.window = real.window;
      globalThis.getComputedStyle = real.getComputedStyle;
      globalThis.requestAnimationFrame = real.requestAnimationFrame;
      globalThis.requestIdleCallback = real.requestIdleCallback;
      globalThis.setTimeout = real.setTimeout;
      if (real.localStorage === undefined) delete globalThis.localStorage;
      else globalThis.localStorage = real.localStorage;
    },
  };
}

test('no browser surface at all -> startBG3D refuses', async () => {
  const realDocument = globalThis.document;
  const realWindow = globalThis.window;
  delete globalThis.document;
  delete globalThis.window;
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), false);
  } finally {
    globalThis.document = realDocument;
    globalThis.window = realWindow;
  }
});

test('reduced motion hands over to the static CSS grid, GL untouched', async () => {
  const env1 = env({ reduced: true });
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), false);
    assert.equal(env1.docEl.dataset.bg3d, 'css-fallback');
    assert.equal(env1.getContextCalls.length, 0);
  } finally { env1.cleanup(); }
});

test('missing WebGL context marks the canvas disabled', async () => {
  const env1 = env({ gl: null });
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), false);
    assert.equal(env1.docEl.dataset.bg3d, 'disabled');
    assert.deepEqual(env1.getContextCalls, ['webgl', 'experimental-webgl']);
  } finally { env1.cleanup(); }
});

test('a throwing getContext also lands on the disabled fallback', async () => {
  const env1 = env({ contextThrows: true });
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), false);
    assert.equal(env1.docEl.dataset.bg3d, 'disabled');
  } finally { env1.cleanup(); }
});

test('missing canvas: started flag is set, nothing is marked or drawn', async () => {
  const env1 = env({ withCanvas: false, gl: mockGL() });
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), false);
    assert.equal(env1.docEl.dataset.bg3d, undefined);
    assert.equal(env1.win.__reascanBG3D__started, true);
  } finally { env1.cleanup(); }
});

test('mocked GL run: idempotent mount, DPR capped at 1.5, loop pauses and resumes on visibility', async () => {
  const env1 = env({ dpr: 3, gl: mockGL() }); // 3 must clamp to 1.5
  try {
    const { startBG3D } = await mod();
    assert.equal(startBG3D(), true);
    assert.equal(env1.docEl.dataset.bg3d, undefined, 'a healthy pipeline marks no fallback');
    // resize() ran at mount: canvas backing store = innerWidth * min(dpr, 1.5)
    assert.equal(env1.canvas.width, 300); // floor(200 * 1.5)
    assert.equal(env1.canvas.height, 150); // floor(100 * 1.5)

    assert.equal(startBG3D(), true, 'second call is the idempotent no-op');
    assert.equal(env1.win.__reascanBG3D__started, true);

    // lazy kick: idle callback -> onVisibility -> first frame scheduled
    env1.doc.hidden = false;
    assert.equal(env1.rafQueue.length, 0);
    env1.idleCbs[0]();
    assert.equal(env1.rafQueue.length, 1);

    // one tick (running) re-schedules the next frame
    env1.rafQueue.shift()(16);
    assert.equal(env1.rafQueue.length, 1);

    // pause: mark hidden, the pending frame still fires once, then stops
    env1.doc.hidden = true;
    for (const fn of [...env1.doc._listeners.visibilitychange ?? []]) fn();
    env1.rafQueue.shift()(50);
    assert.equal(env1.rafQueue.length, 0, 'no frame may be scheduled while the tab is hidden');

    // resume: visible again -> the loop comes back
    env1.doc.hidden = false;
    for (const fn of [...env1.doc._listeners.visibilitychange ?? []]) fn();
    assert.equal(env1.rafQueue.length, 1, 'resume must re-arm the RAF loop');
  } finally { env1.cleanup(); }
});
