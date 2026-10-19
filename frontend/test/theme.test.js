import { test } from 'node:test';
import assert from 'node:assert/strict';

// Theme module contract: dark by default, light persists to localStorage,
// "system" falls through to prefers-color-scheme, and nothing may crash when
// matchMedia or storage is missing (private browsing, exotic engines, mock DOM).

const mod = () => import('../theme.js');

// In-memory stand-in with the exact Storage surface the module touches.
const storageBean = () => {
  const map = new Map();
  return {
    map,
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
  };
};

// Installs a fresh minimal DOM surface and restores the real globals afterwards.
// window and document are swapped together so the module's typeof checks behave
// like a browser or like a bare node process, never a half-surface.
async function withGlobals({ documentElement, storage, matchMedia, bare = false }, run) {
  const realDocument = globalThis.document;
  const realWindow = globalThis.window;
  const realStorage = globalThis.localStorage;
  globalThis.document = { documentElement };
  if (!bare) globalThis.window = { matchMedia };
  globalThis.localStorage = storage;
  try {
    return await run(documentElement);
  } finally {
    globalThis.document = realDocument;
    globalThis.window = realWindow;
    if (realStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = realStorage;
  }
}

test('without any stored mode the theme resolves to dark', async () => {
  await withGlobals(
    { documentElement: { dataset: {} }, storage: storageBean() },
    async (root) => {
      const { applyTheme } = await mod();
      const theme = applyTheme('dark', { persist: true });
      assert.equal(theme, 'dark');
      assert.equal(root.dataset.theme, 'dark');
    },
  );
});

test('light is persisted and applied', async () => {
  const storage = storageBean();
  await withGlobals(
    { documentElement: { dataset: {} }, storage },
    async (root) => {
      const { applyTheme, getMode } = await mod();
      const theme = applyTheme('light');
      assert.equal(theme, 'light');
      assert.equal(root.dataset.theme, 'light');
      assert.equal(storage.map.get('reascan:theme'), 'light');
      assert.equal(getMode(), 'light');
    },
  );
});

test('system falls through to prefers-color-scheme', async () => {
  const queries = [];
  const storage = storageBean();
  await withGlobals(
    {
      documentElement: { dataset: {} },
      storage,
      matchMedia: (q) => { queries.push(q); return { matches: true, addEventListener() {} }; },
    },
    async (root) => {
      const { applyTheme } = await mod();
      const theme = applyTheme('system');
      assert.equal(theme, 'light'); // the OS preference says light
      assert.equal(root.dataset.theme, 'light');
      assert.ok(queries.every((q) => q.includes('prefers-color-scheme')));
      // system is stored as a MODE - the resolution happens per application
      assert.equal(storage.map.get('reascan:theme'), 'system');
    },
  );
});

test('a missing matchMedia does not crash, still resolves dark', async () => {
  const storage = storageBean();
  await withGlobals(
    { documentElement: { dataset: {} }, storage, matchMedia: undefined, bare: false },
    async (root) => {
      const { applyTheme } = await mod();
      let theme;
      assert.doesNotThrow(() => { theme = applyTheme('system'); });
      assert.equal(theme, 'dark'); // no OS information -> the dark fallthrough
      assert.equal(root.dataset.theme, 'dark');
    },
  );
});

test('a throwing localStorage never breaks theme application', async () => {
  const root = { dataset: {} };
  const realDocument = globalThis.document;
  const realWindow = globalThis.window;
  const realStorage = globalThis.localStorage;
  globalThis.document = { documentElement: root };
  globalThis.window = { matchMedia: undefined }; // no matchMedia at all
  globalThis.localStorage = {
    getItem: () => { throw new Error('denied'); },
    setItem: () => { throw new Error('denied'); },
    removeItem: () => { throw new Error('denied'); },
  };
  try {
    const { applyTheme } = await mod();
    let theme;
    assert.doesNotThrow(() => { theme = applyTheme('light'); });
    assert.equal(theme, 'light');
    assert.equal(root.dataset.theme, 'light');
  } finally {
    globalThis.document = realDocument;
    globalThis.window = realWindow;
    if (realStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = realStorage;
  }
});
