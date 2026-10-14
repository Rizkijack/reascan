import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAdapter, reaOutcome } from './server.js';
import { _resetBinaryCache } from './lib/reaCli.js';

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
    assert.deepEqual(await ok.json(), {
      status: 'ok',
      tools_available: ['fingerprint', 'jsBundle', 'browserCapture', 'jsDeep'],
      rea_tools: ['browser.capture', 'js.analyzeDeep'],
    });
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

// The fixture is a POSIX shell script and reaCli spawns without a shell, so it
// cannot run on Windows — same reasoning as reaCli.test.js. These run on the VM,
// which is where `rea` lives.
const needsPosix = process.platform === 'win32'
  ? { skip: 'fixture is a POSIX shell script; Windows spawn cannot execute it' }
  : {};

// The REA deep-analysis envelope, distilled by distilJsAnalysis, carries its own
// limitations array. server.js must hoist those into verdict.limitations and
// strip them from the section payload — the same shape fingerprint and js_bundles
// ship. Before the fix the array was dropped on the floor: the engine's own
// "could not parse bundle N" never reached the reader, which is exactly the
// silent drop AGENTS.md forbids.
//
// The unit cases below pin reaOutcome directly (offline, any platform); the
// end-to-end case drives the same logic through HTTP with a fake rea binary.
test('reaOutcome hoists limitations and strips them from the payload', () => {
  const capture = reaOutcome({
    ok: true,
    capture: {
      final_url: 'https://example.com/',
      screenshot: 'data:image/png;base64,AAAA',
      limitations: ['screenshot step failed on step 2', 42],
    },
  });
  assert.deepEqual(capture.limitations, ['screenshot step failed on step 2', '42']);
  assert.equal(capture.data.limitations, undefined);
  assert.equal(capture.data.final_url, 'https://example.com/');
  assert.equal(capture.data.screenshot, 'data:image/png;base64,AAAA');

  const analysis = reaOutcome({
    ok: true,
    analysis: { modules: 7, parse_failures: 1, limitations: ['could not parse bundle-3.js'] },
  });
  assert.deepEqual(analysis.limitations, ['could not parse bundle-3.js']);
  assert.equal(analysis.data.limitations, undefined);
  assert.equal(analysis.data.modules, 7);

  // No limitations at all: payload passes through untouched, task is clean.
  const clean = reaOutcome({ ok: true, capture: { final_url: 'https://example.com/' } });
  assert.deepEqual(clean.limitations, []);
  assert.equal(clean.data.final_url, 'https://example.com/');

  // Neither capture nor analysis (ok:true with no payload) degrades to null.
  assert.deepEqual(reaOutcome({ ok: true }), { data: null, limitations: [] });
});

test('REA limitations reach the verdict and stay out of the section payload', needsPosix, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'reascan-fake-rea-'));
  const bin = join(dir, 'rea');
  await writeFile(bin, '#!/bin/sh\n'
    + 'echo \'{"normalized_result":{"statistics":{"modules":7,"findings":2,"visited_ast_nodes":99,"parse_failures":1},'
    + '"semantic_graph":{"coverage":{"status":"partial"},"unknowns":[]},'
    + '"limitations":["engine could not parse bundle-3.js"]},"confidence":"derived\'}\'');
  await chmod(bin, 0o755);

  const prev = process.env.REA_BIN;
  process.env.REA_BIN = bin;
  _resetBinaryCache();
  try {
    await withServer({}, async (call) => {
      const r = await call('/analyze', authed({ url: 'https://example.com/', categories: ['jsDeep'] }));
      assert.equal(r.status, 200);
      const { findings } = await r.json();

      assert.ok(findings.verdict.limitations.includes('engine could not parse bundle-3.js'),
        `expected the engine limitation in the verdict, got ${JSON.stringify(findings.verdict.limitations)}`);

      // The section keeps its data; the limitations field is the verdict's job.
      assert.equal(findings.js_deep.limitations, undefined);
      assert.equal(findings.js_deep.modules, 7);
      assert.equal(findings.js_deep.coverage_status, 'partial');
      assert.equal(findings.js_deep.parse_failures, 1);
    });
  } finally {
    if (prev === undefined) delete process.env.REA_BIN;
    else process.env.REA_BIN = prev;
    _resetBinaryCache();
  }
});
