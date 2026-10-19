// theme.js additions NOT covered by theme.test.js: the data-theme attribute may
// only ever be 'dark' or 'light' (whatever the mode, incl. unknown modes), the
// segmented control pins aria-pressed, and the system live-follow must not
// hijack a later manual choice (the listener stays wired but repaints are
// guarded on currentMode).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, fire, storageBean } from './dom-shim.js';

async function withGlobals({ storage, matchMedia, group }, run) {
  const root = new El('html');
  const realDocument = globalThis.document;
  const realWindow = globalThis.window;
  const realStorage = globalThis.localStorage;
  globalThis.document = {
    readyState: 'loading', // auto-boot registers DOMContentLoaded, never fires
    documentElement: root,
    getElementById: (id) => (id === 'theme-toggle' ? group : null),
    addEventListener() {},
    removeEventListener() {},
  };
  globalThis.window = { matchMedia };
  globalThis.localStorage = storage;
  try {
    await run(root);
  } finally {
    globalThis.document = realDocument;
    globalThis.window = realWindow;
    if (realStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = realStorage;
  }
}

const noopMq = (matches) => ({
  matches,
  addEventListener() {},
  removeEventListener() {},
});

test('data-theme stays in {dark, light} for every mode, including unknown', async () => {
  const cases = [
    ['light', 'light'],
    ['dark', 'dark'],
    ['bogus', 'dark'], // unknown mode falls back to the dark default
  ];
  for (const [mode, expected] of cases) {
    await withGlobals(
      { storage: storageBean(), matchMedia: () => noopMq(false) },
      async (root) => {
        const { applyTheme } = await import('../theme.js?case=validity');
        assert.equal(applyTheme(mode, { persist: false }), expected);
        assert.equal(root.dataset.theme, expected);
      },
    );
  }
});

test('boot applies a stored mode and still resolves a valid theme', async () => {
  const storage = storageBean();
  storage.setItem('reascan:theme', 'system');
  await withGlobals(
    { storage, matchMedia: () => noopMq(true) }, // OS prefers light
    async (root) => {
      const { initTheme, getTheme } = await import('../theme.js?case=boot');
      initTheme(document);
      assert.equal(getTheme(), 'light');
      assert.equal(root.dataset.theme, 'light');
    },
  );
});

test('system race: a late OS change must not repaint after a manual choice', async () => {
  const storage = storageBean();
  const handlers = [];
  let osPrefersLight = false;
  const mq = {
    get matches() { return osPrefersLight; },
    addEventListener: (_t, fn) => handlers.push(fn),
    removeEventListener() {},
  };
  const group = new El('div');
  const btns = {};
  for (const mode of ['light', 'dark', 'system']) {
    const b = new El('button');
    b.dataset.mode = mode;
    btns[mode] = b;
    group.appendChild(b);
  }
  await withGlobals(
    { storage, matchMedia: () => mq, group },
    async (root) => {
      const { initTheme, getMode } = await import('../theme.js?case=race');
      initTheme(document);
      const fireChanges = () => { for (const fn of [...handlers]) fn(); };
      const pressed = (mode) => btns[mode].getAttribute('aria-pressed');

      assert.equal(getMode(), 'dark'); // boot default
      assert.equal(root.dataset.theme, 'dark');

      fire(btns.system, 'click');
      assert.equal(getMode(), 'system');
      assert.equal(root.dataset.theme, 'dark'); // OS is dark right now
      assert.equal(storage.map.get('reascan:theme'), 'system');

      // OS flips to light while system is active -> live follow repaints
      osPrefersLight = true;
      fireChanges();
      assert.equal(root.dataset.theme, 'light');

      // the user picks light manually (dark has its own RED test below: the
      // resolveTheme contract is broken for explicit dark on a light OS).
      fire(btns.light, 'click');
      assert.equal(getMode(), 'light');
      assert.equal(root.dataset.theme, 'light');
      assert.equal(storage.map.get('reascan:theme'), 'light');

      // race: the system listener is still wired, but a later OS flip must be
      // ignored once the user has chosen a concrete mode
      osPrefersLight = !osPrefersLight;
      fireChanges();
      assert.equal(root.dataset.theme, 'light', 'manual light must survive OS changes');

      // segmented control a11y state
      assert.equal(pressed('light'), 'true');
      assert.equal(pressed('system'), 'false');
      assert.equal(pressed('dark'), 'false');
      assert.equal(btns.light.classList.contains('is-active'), true);
    },
  );
});

test('legacy engines: addListener fallback still reproduces the live follow', async () => {
  const storage = storageBean();
  const legacyHandlers = [];
  let osPrefersLight = false;
  const mq = {
    get matches() { return osPrefersLight; },
    // deliberately no addEventListener - only the deprecated surface
    addListener: (fn) => legacyHandlers.push(fn),
  };
  const group = new El('div');
  for (const mode of ['light', 'dark', 'system']) {
    const b = new El('button');
    b.dataset.mode = mode;
    group.appendChild(b);
  }
  await withGlobals(
    { storage, matchMedia: () => mq, group },
    async (root) => {
      const { initTheme, applyTheme } = await import('../theme.js?case=legacy');
      initTheme(document);
      applyTheme('system', { persist: false });
      assert.equal(legacyHandlers.length, 1, 'the listener must reach the legacy API');
      assert.equal(root.dataset.theme, 'dark');
      osPrefersLight = true;
      for (const fn of [...legacyHandlers]) fn();
      assert.equal(root.dataset.theme, 'light', 'system mode still follows on legacy engines');
      osPrefersLight = false;
      applyTheme('dark', { persist: false });
      for (const fn of [...legacyHandlers]) fn();
      assert.equal(root.dataset.theme, 'dark');
    },
  );
});

// RED - pinned bug, reported to the orchestrator, deliberately not fixed here.
// Contract: an explicit dark/light choice must beat the OS preference. The
// anti-flash bootstrap in index.html gets this right (L19-22: `let theme = mode`,
// only "system" consults matchMedia), but theme.js resolveTheme() early-returns
// for "light" only and lets an explicit 'dark' fall through to the OS query.
// On a machine with prefers-color-scheme: light, clicking Dark paints LIGHT.
test('contract: explicit dark ignores the OS preference (resolveTheme vs bootstrap)', async () => {
  const storage = storageBean();
  await withGlobals(
    { storage, matchMedia: () => noopMq(true) }, // OS prefers light
    async (root) => {
      const { applyTheme, getTheme } = await import('../theme.js?case=darkbug');
      const theme = applyTheme('dark', { persist: false });
      assert.equal(theme, 'dark');
      assert.equal(getTheme(), 'dark');
      assert.equal(root.dataset.theme, 'dark');
    },
  );
});
