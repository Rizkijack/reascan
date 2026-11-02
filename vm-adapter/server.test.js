import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
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
      tools_available: ['fingerprint', 'jsBundle', 'browserCapture', 'jsDeep', 'webInspect'],
      rea_tools: ['browser.capture', 'js.analyzeDeep', 'web.inspectPage'],
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
    // The ignored category must announce itself: a report that ran nothing
    // without saying so reads as a real (empty) analysis — the same silent
    // drop the evidence standard forbids for failed bundles.
    assert.ok(
      body.findings.verdict.limitations.some((l) => /unknown categories ignored: nonsense/.test(l)),
      JSON.stringify(body.findings.verdict.limitations),
    );
  });
});

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

  // The web inspect category ships its distilled inspection through the same
  // limitations-hoisting contract.
  const inspection = reaOutcome({
    ok: true,
    inspection: { scripts_total: 3, limitations: ['inspect-web-event-listeners failed: timed out'] },
  });
  assert.deepEqual(inspection.limitations, ['inspect-web-event-listeners failed: timed out']);
  assert.equal(inspection.data.limitations, undefined);
  assert.equal(inspection.data.scripts_total, 3);

  // No limitations at all: payload passes through untouched, task is clean.
  const clean = reaOutcome({ ok: true, capture: { final_url: 'https://example.com/' } });
  assert.deepEqual(clean.limitations, []);
  assert.equal(clean.data.final_url, 'https://example.com/');

  // Neither capture nor analysis (ok:true with no payload) degrades to null.
  assert.deepEqual(reaOutcome({ ok: true }), { data: null, limitations: [] });
});

test('REA limitations reach the verdict and stay out of the section payload', async () => {
  // A `.mjs` fixture, not a shell script: resolveSpawn runs it through node, so
  // this case executes on every platform. It had been skipped on Windows, and on
  // POSIX its hand-escaped `echo` quoting did not actually emit the JSON it
  // claimed to — so the invariant below had never really been checked anywhere.
  const dir = await mkdtemp(join(tmpdir(), 'reascan-fake-rea-'));
  const bin = join(dir, 'rea.mjs');
  const envelope = {
    normalized_result: {
      statistics: { modules: 7, findings: 2, visited_ast_nodes: 99, parse_failures: 1 },
      semantic_graph: { coverage: { status: 'partial' }, unknowns: [] },
      limitations: ['engine could not parse bundle-3.js'],
    },
    confidence: 'derived',
  };
  await writeFile(bin, `process.stdout.write(${JSON.stringify(`${JSON.stringify(envelope)}\n`)});`);

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

// The web inspect category end to end: server -> callReaTool -> inspectWebPage
// -> four REA CLI invocations (inspect / listeners / webmcp / export), all
// served by one fake binary that branches on the sub-command. Asserted:
// findings.web_inspect carries the distilled shape, engine limitations land in
// the verdict, and the script text REA retained in the capture never leaks into
// the payload — the marker here plays the retained source's part.
test('webInspect degrades on the server when the browser env is down', async () => {
  // The four-CLI happy path is pinned against the fake binary in
  // lib/reaCli.test.js with an injected browser env. Here the server-level
  // contract is pinned in its failure shape, deterministic on any box: a
  // browser prerequisite that cannot come up degrades the section to null and
  // names the cause in verdict.limitations — it never fails the report.
  const dir = await mkdtemp(join(tmpdir(), 'reascan-fake-rea-'));
  const bin = join(dir, 'rea.mjs');
  await writeFile(bin, 'process.stdout.write("{}\\n");', 'utf8');
  const envPrev = {};
  const ENV_KEYS = ['REA_BIN', 'REA_CHROME_BIN', 'REA_CDP_PORT',
    'https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'];
  for (const k of ENV_KEYS) envPrev[k] = process.env[k];
  process.env.REA_BIN = bin;
  process.env.REA_CHROME_BIN = 'C:/definitely/not/installed/chrome.exe';
  process.env.REA_CDP_PORT = '19723';
  delete process.env.https_proxy; delete process.env.HTTPS_PROXY;
  delete process.env.http_proxy; delete process.env.HTTP_PROXY;
  _resetBinaryCache();
  try {
    await withServer({}, async (call) => {
      const r = await call('/analyze', authed({ url: 'https://example.com/', categories: ['webInspect'] }));
      assert.equal(r.status, 200);
      const { findings } = await r.json();
      assert.equal(findings.web_inspect, null, 'nothing is faked when the browser env is down');
      assert.ok(
        findings.verdict.limitations.some((l) => /web\.inspectPage: Chromium CDP did not come up/.test(l) && /could not be started/.test(l)),
        `the failure must be named, got: ${JSON.stringify(findings.verdict.limitations)}`,
      );
      assert.equal(findings.verdict.confidence, 'low');
    });
  } finally {
    for (const k of ENV_KEYS) {
      if (envPrev[k] === undefined) delete process.env[k];
      else process.env[k] = envPrev[k];
    }
    _resetBinaryCache();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});
