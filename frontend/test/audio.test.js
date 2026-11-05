// audio.js contract: no Web Audio -> the control disables itself; with Web
// Audio -> the toggle builds the generated graph, flips aria-pressed/label,
// and suspends/resumes with tab visibility. Node has no AudioContext, so the
// graph is a stub that only records node creation and state changes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, createDocument, fire, fireDocument } from './dom-shim.js';

function audioParam() {
  return {
    value: 0,
    setValueAtTime(v) { this.value = v; },
    exponentialRampToValueAtTime(v) { this.value = v; },
    cancelScheduledValues() {},
    linearRampToValueAtTime(v) { this.value = v; },
  };
}

function audioNode(extra = {}) {
  const node = {
    connect() { return this; },
    disconnect() {},
    start() {},
    stop() {},
    ...extra,
  };
  return node;
}

function mockContext() {
  const ctx = {
    state: 'suspended',
    currentTime: 0,
    destination: {},
    created: { gain: 0, osc: 0, filter: 0, delay: 0 },
    gains: [],
    createGain() {
      ctx.created.gain += 1;
      const node = audioNode({ gain: audioParam() });
      ctx.gains.push(node.gain);
      return node;
    },
    createOscillator() {
      ctx.created.osc += 1;
      return audioNode({ type: 'sine', frequency: audioParam(), detune: audioParam() });
    },
    createBiquadFilter() {
      ctx.created.filter += 1;
      return audioNode({ type: 'lowpass', frequency: audioParam(), Q: audioParam() });
    },
    createDelay() { ctx.created.delay += 1; return audioNode({ delayTime: audioParam() }); },
    async resume() { ctx.state = 'running'; },
    async suspend() { ctx.state = 'suspended'; },
    async close() { ctx.state = 'closed'; },
  };
  return ctx;
}

async function withEnv(AudioContext, run) {
  const button = new El('button');
  const label = new El('span');
  label.className = 'sound-label';
  label.textContent = 'SOUND OFF';
  button.appendChild(label);
  const doc = createDocument({ ids: { 'sound-toggle': button } });
  const listeners = {};
  const win = {
    AudioContext,
    addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
    listeners,
  };
  const real = {
    document: globalThis.document,
    window: globalThis.window,
    localStorage: globalThis.localStorage,
  };
  globalThis.document = doc;
  globalThis.window = win;
  try {
    await run({ button, label, doc, win });
  } finally {
    globalThis.document = real.document;
    globalThis.window = real.window;
    if (real.localStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = real.localStorage;
  }
}

const mod = (name) => import(`../audio.js?case=${name}`);

test('midiToHz anchors A4 at 440 and doubles one octave up', async () => {
  const { midiToHz } = await mod('math');
  assert.equal(midiToHz(69), 440);
  assert.equal(midiToHz(81), 880);
  assert.equal(Math.round(midiToHz(57) * 100) / 100, 220);
});

test('without Web Audio the control disables itself instead of throwing', async () => {
  await withEnv(undefined, async ({ button, label }) => {
    const { initAudio } = await mod('unsupported');
    assert.equal(initAudio(), false);
    assert.equal(button.disabled, true);
    assert.equal(label.textContent, 'SOUND N/A');
    assert.match(button.getAttribute('aria-label'), /unavailable/i);
  });
});

test('start builds the pad/arp graph, updates the control, and stop reverses it', async () => {
  let lastCtx = null;
  class FakeAudioContext {
    constructor() {
      lastCtx = mockContext();
      return lastCtx;
    }
  }

  await withEnv(FakeAudioContext, async ({ button, label }) => {
    const { initAudio, startSound, stopSound, toggleSound } = await mod('toggle');
    assert.equal(initAudio(), true);
    assert.equal(button.getAttribute('aria-pressed'), 'false');
    assert.equal(label.textContent, 'SOUND OFF');

    assert.equal(await startSound(), true);
    assert.equal(lastCtx.state, 'running');
    assert.ok(lastCtx.created.osc >= 9, 'one LFO plus eight pad oscillators');
    assert.ok(lastCtx.created.filter >= 1, 'the pad runs through a low-pass filter');
    assert.equal(lastCtx.gains[0].value, 0.875, 'master output is 2.5x the original 0.35 level');
    assert.equal(button.getAttribute('aria-pressed'), 'true');
    assert.equal(label.textContent, 'SOUND ON');
    assert.equal(button.classList.contains('is-on'), true);

    assert.equal(stopSound(), true);
    assert.equal(button.getAttribute('aria-pressed'), 'false');
    assert.equal(label.textContent, 'SOUND OFF');
    assert.equal(stopSound(), false, 'a second stop is a no-op');

    assert.equal(await toggleSound(), true);
    assert.equal(await toggleSound(), false, 'toggle stops an enabled soundtrack');
  });
});

test('visibility changes suspend and resume the running context', async () => {
  let lastCtx = null;
  class FakeAudioContext {
    constructor() {
      lastCtx = mockContext();
      return lastCtx;
    }
  }

  await withEnv(FakeAudioContext, async ({ doc }) => {
    const { initAudio, startSound, stopSound } = await mod('visibility');
    initAudio();
    await startSound();
    assert.equal(lastCtx.state, 'running');

    doc.hidden = true;
    fireDocument(doc, 'visibilitychange');
    assert.equal(lastCtx.state, 'suspended', 'a hidden tab must not keep synthesizing');

    doc.hidden = false;
    fireDocument(doc, 'visibilitychange');
    assert.equal(lastCtx.state, 'running', 'a visible tab resumes the soundtrack');
    stopSound();
  });
});

test('the control click is wired to the toggle', async () => {
  let lastCtx = null;
  class FakeAudioContext {
    constructor() {
      lastCtx = mockContext();
      return lastCtx;
    }
  }

  await withEnv(FakeAudioContext, async ({ button, label }) => {
    const { initAudio } = await mod('click');
    initAudio();
    fire(button, 'click');
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(lastCtx?.state, 'running');
    assert.equal(label.textContent, 'SOUND ON');

    fire(button, 'click');
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(button.getAttribute('aria-pressed'), 'false');
    assert.equal(label.textContent, 'SOUND OFF');
  });
});
