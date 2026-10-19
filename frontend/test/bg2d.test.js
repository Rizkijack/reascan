import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, createDocument } from './dom-shim.js';

// bg2d.js contract, WITHOUT any real Chrome: reduced motion -> CSS grid handoff
// (data-bg2d="css-fallback"), no/ throwing 2D context -> "disabled", startup is
// idempotent, the backing pixel ratio is capped at 1.5, the loop pauses on
// visibilitychange instead of rendering into a hidden tab, and the scene keeps
// its colours as plain CSS strings rather than blend-mode tricks.

const mod = () => import('../bg2d.js');

// A 2D stub that accepts every draw call. The scene shape is out of scope here -
// the fallback/beam wiring is what is pinned.
function mockCtx() {
  const calls = { gradients: 0, strokes: 0, destinationOut: 0, composite: [] };
  return {
    calls,
    createRadialGradient() { calls.gradients++; return { addColorStop() {} }; },
    clearRect() {}, setTransform() {}, save() {}, restore() {}, translate() {},
    beginPath() {}, moveTo() {}, lineTo() {}, arc() {}, fill() {}, fillRect() {},
    stroke() { calls.strokes++; },
    fillStyle: '', strokeStyle: '', lineWidth: 1, globalAlpha: 1,
    globalCompositeOperation: '',
    set globalCompositeOperationOp(v) {},
  };
}

function env({ dpr = 1, reduced = false, ctx = null, contextThrows = false, withCanvas = true } = {}) {
  const canvas = new El('canvas');
  const getContextCalls = [];
  canvas.getContext = (type) => {
    getContextCalls.push(type);
    if (contextThrows) throw new Error('broken driver');
    return ctx;
  };
  const ids = withCanvas ? { bg2d: canvas } : {};
  const docEl = new El('html');
  const doc = createDocument({ ids, documentElement: docEl });
  const matchMedia = (q) => ({ matches: reduced && q.includes('prefers-reduced-motion'), addEventListener() {} });
  const win = {
    matchMedia,
    devicePixelRatio: dpr,
    innerWidth: 200,
    innerHeight: 100,
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

test('no browser surface at all -> startBG2D refuses', async () => {
  const realDocument = globalThis.document;
  const realWindow = globalThis.window;
  delete globalThis.document;
  delete globalThis.window;
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), false);
  } finally {
    globalThis.document = realDocument;
    globalThis.window = realWindow;
  }
});

test('reduced motion hands over to the static CSS grid, context untouched', async () => {
  const env1 = env({ reduced: true, ctx: mockCtx() });
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), false);
    assert.equal(env1.docEl.dataset.bg2d, 'css-fallback');
    assert.equal(env1.getContextCalls.length, 0);
  } finally { env1.cleanup(); }
});

test('missing 2D context marks the canvas disabled', async () => {
  const env1 = env({ ctx: null });
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), false);
    assert.equal(env1.docEl.dataset.bg2d, 'disabled');
    assert.deepEqual(env1.getContextCalls, ['2d']);
  } finally { env1.cleanup(); }
});

test('a throwing getContext also lands on the disabled fallback', async () => {
  const env1 = env({ contextThrows: true });
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), false);
    assert.equal(env1.docEl.dataset.bg2d, 'disabled');
  } finally { env1.cleanup(); }
});

test('missing canvas: started flag is set, nothing is marked or drawn', async () => {
  const env1 = env({ withCanvas: false, ctx: mockCtx() });
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), false);
    assert.equal(env1.docEl.dataset.bg2d, undefined);
    assert.equal(env1.win.__reascanBG2D__started, true);
  } finally { env1.cleanup(); }
});

test('mocked run: idempotent mount, DPR capped at 1.5, loop pauses and resumes on visibility', async () => {
  const ctx = mockCtx();
  const env1 = env({ dpr: 3, ctx }); // 3 must clamp to 1.5
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), true);
    assert.equal(env1.docEl.dataset.bg2d, undefined, 'a healthy pipeline marks no fallback');
    // resize() ran at mount: canvas backing store = innerWidth * min(dpr, 1.5)
    assert.equal(env1.canvas.width, 300); // floor(200 * 1.5)
    assert.equal(env1.canvas.height, 150); // floor(100 * 1.5)

    assert.equal(startBG2D(), true, 'second call is the idempotent no-op');
    assert.equal(env1.win.__reascanBG2D__started, true);

    // lazy kick: idle callback -> onVisibility -> first frame scheduled
    env1.doc.hidden = false;
    assert.equal(env1.rafQueue.length, 0);
    env1.idleCbs[0]();
    assert.equal(env1.rafQueue.length, 1);

    // one tick (running) draws and re-schedules: two grid layers per frame
    env1.rafQueue.shift()(16);
    assert.equal(env1.rafQueue.length, 1);
    assert.equal(ctx.calls.strokes, 2, 'both grid layers are stroked each frame');

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

test('the centre pass punches through with destination-out, never an additive blend', async () => {
  const ctx = mockCtx();
  const composites = [];
  ctx.setComposite = (v) => composites.push(v);
  const env1 = env({ ctx });
  try {
    const { startBG2D } = await mod();
    assert.equal(startBG2D(), true);
    env1.doc.hidden = false;
    env1.idleCbs[0]();
    // Proxy the property writes a real 2D context would record.
    Object.defineProperty(ctx, 'globalCompositeOperation', {
      get() { return this._composite ?? 'source-over'; },
      set(v) { this._composite = v; composites.push(v); },
      configurable: true,
    });
    env1.rafQueue.shift()(16);

    assert.ok(composites.includes('destination-out'), 'the centre pass must erase, not lighten');
    assert.ok(!composites.includes('lighter'), 'additive blending would blow out the light theme');
    assert.equal(ctx._composite, 'source-over', 'the pass restores source-over before returning');
  } finally { env1.cleanup(); }
});