import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAdapter } from './server.js';

const KEY = 'test-key-0123456789abcdef';

// Port 0 lets the OS pick a free port, so these tests never collide with a
// running adapter and never bind a fixed port.
async function withServer(env, run) {
  const server = createAdapter({ API_KEY: KEY, ...env });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await run((path, init) => fetch(`http://127.0.0.1:${port}${path}`, init));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const authed = (body) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-api-key': KEY },
  body: JSON.stringify(body),
});

test('health responds only with the correct key', async () => {
  await withServer({}, async (call) => {
    const ok = await call('/health', { headers: { 'x-api-key': KEY } });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { status: 'ok', tools_available: ['fingerprint', 'jsBundle'] });
  });
});

test('a missing key is rejected', async () => {
  await withServer({}, async (call) => {
    for (const headers of [{}, { 'x-api-key': '' }, { 'x-api-key': 'wrong-key-000000000000' }]) {
      const r = await call('/health', { headers });
      assert.equal(r.status, 401, `expected 401 for ${JSON.stringify(headers)}`);
      assert.equal((await r.json()).status, 'error');
    }
  });
});

test('an unset API_KEY refuses to serve rather than running open', async () => {
  await withServer({ API_KEY: '' }, async (call) => {
    const r = await call('/health', { headers: { 'x-api-key': '' } });
    assert.equal(r.status, 500);
    assert.match((await r.json()).error, /API_KEY is not configured/);
  });
});

test('a key of a different length is refused without throwing', async () => {
  // timingSafeEqual throws on mismatched buffer lengths; the length check has to
  // come first or a short key would crash the request.
  await withServer({}, async (call) => {
    const r = await call('/health', { headers: { 'x-api-key': 'short' } });
    assert.equal(r.status, 401);
  });
});

test('a blocked URL returns 422 and never reaches analysis', async () => {
  await withServer({}, async (call) => {
    for (const url of ['http://127.0.0.1/', 'http://169.254.169.254/', 'file:///etc/passwd']) {
      const r = await call('/analyze', authed({ url }));
      assert.equal(r.status, 422, `${url} should be refused`);
      assert.equal((await r.json()).status, 'error');
    }
  });
});

test('a malformed body is a 422, not a crash', async () => {
  await withServer({}, async (call) => {
    const notJson = await call('/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': KEY },
      body: 'not json at all',
    });
    assert.equal(notJson.status, 422);

    const noUrl = await call('/analyze', authed({}));
    assert.equal(noUrl.status, 422);
  });
});

test('an oversized body is refused rather than buffered', async () => {
  await withServer({}, async (call) => {
    const r = await call('/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': KEY },
      body: JSON.stringify({ url: 'https://example.com/', pad: 'x'.repeat(20000) }),
    });
    assert.equal(r.status, 422);
    assert.match((await r.json()).error, /too large/);
  });
});

test('unknown routes and methods are 404, not 500', async () => {
  await withServer({}, async (call) => {
    assert.equal((await call('/nope', { headers: { 'x-api-key': KEY } })).status, 404);
    assert.equal((await call('/analyze', { headers: { 'x-api-key': KEY } })).status, 404);
  });
});

test('every response is JSON with status done or error', async () => {
  await withServer({}, async (call) => {
    for (const [path, init] of [
      ['/health', { headers: { 'x-api-key': KEY } }],
      ['/health', {}],
      ['/nope', { headers: { 'x-api-key': KEY } }],
      ['/analyze', authed({ url: 'http://127.0.0.1/' })],
      ['/analyze', authed({ url: 'not-a-url' })],
    ]) {
      const r = await call(path, init);
      const body = await r.json();
      assert.match(r.headers.get('content-type'), /application\/json/);
      assert.ok(['error', 'ok', 'done'].includes(body.status), `unexpected status ${body.status}`);
    }
  });
});

test('a live analysis returns the full findings shape', async () => {
  await withServer({}, async (call) => {
    const r = await call('/analyze', authed({ url: 'https://example.com/', categories: ['fingerprint'] }));
    assert.equal(r.status, 200);

    const body = await r.json();
    assert.equal(body.status, 'ok');
    assert.ok(typeof body.duration_ms === 'number');

    const f = body.findings;
    assert.equal(f.url, 'https://example.com/');
    assert.ok(Date.parse(f.timestamp) > 0);
    assert.ok(Array.isArray(f.fingerprint.findings));
    assert.ok(Array.isArray(f.js_bundles));
    assert.ok(['high', 'medium', 'low'].includes(f.verdict.confidence));
    assert.ok(Array.isArray(f.verdict.limitations));
    assert.ok(Array.isArray(f.verdict.unknowns));
  });
});

test('a category that was not requested is skipped, not faked', async () => {
  await withServer({}, async (call) => {
    const r = await call('/analyze', authed({ url: 'https://example.com/', categories: ['fingerprint'] }));
    const body = await r.json();
    assert.deepEqual(body.findings.js_bundles, []);
    assert.ok(body.findings.fingerprint.findings.length > 0);
  });
});

test('unknown categories produce a low-confidence report rather than an error', async () => {
  await withServer({}, async (call) => {
    const r = await call('/analyze', authed({ url: 'https://example.com/', categories: ['nonsense'] }));
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.findings.verdict.confidence, 'low');
    assert.deepEqual(body.findings.fingerprint.findings, []);
  });
});