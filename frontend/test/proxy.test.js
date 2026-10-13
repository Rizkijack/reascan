import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { onRequestPost } from '../functions/api/analyze.js';

// onRequestPost uses only web APIs (Request/Response/fetch/AbortController) plus
// node:dns, so it runs under node:test against a real local server. This is the
// only place the proxy path is exercised end to end — the offline tests cover
// validateUrl but never reach the adapter call.

const FINDINGS = {
  url: 'https://example.com/',
  timestamp: '2026-10-13T00:00:00.000Z',
  fingerprint: { findings: [], cdn: null, tls: null },
  js_bundles: [],
  verdict: { confidence: 'low', limitations: [], unknowns: [] },
};

// A stand-in adapter that records what the edge sent it and replies with a
// scripted status/body.
async function withFakeAdapter(handler, run) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = null;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        body = Buffer.concat(chunks).toString('utf8');
      }
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      handler(res, body);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await run({ url: `http://127.0.0.1:${port}`, seen });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const post = (body, env = { VM_ADAPTER_URL: 'http://127.0.0.1:1', API_KEY: 'k' }) =>
  onRequestPost({
    request: new Request('https://reascan.pages.dev/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    }),
    env,
  });

const call = (url, categories, env) =>
  post(JSON.stringify({ url, categories }), env);

// A public IP literal: validateUrl accepts it without a DNS round-trip, so the
// proxy suite stays offline and deterministic.
const PUBLIC = 'http://93.184.216.34/';

test('a malformed body is a 422 JSON response', async () => {
  const res = await post('not json at all');
  assert.equal(res.status, 422);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await res.json(), { status: 'error', error: 'body is not valid JSON' });
});

test('a blocked URL is refused before the adapter is contacted', async () => {
  await withFakeAdapter(
    (res) => res.end(JSON.stringify({ status: 'ok', findings: FINDINGS })),
    async ({ url, seen }) => {
      const res = await call('http://169.254.169.254/latest/meta-data/', ['fingerprint'], {
        VM_ADAPTER_URL: url,
        API_KEY: 'k',
      });
      assert.equal(res.status, 422);
      assert.match((await res.json()).error, /blocked|private/);
      assert.equal(seen.length, 0, 'adapter must not be reached for a blocked URL');
    },
  );
});

test('a missing engine config is a 500, not a silent success', async () => {
  for (const env of [{}, { VM_ADAPTER_URL: 'http://127.0.0.1:1' }, { API_KEY: 'k' }]) {
    const res = await call(PUBLIC, ['fingerprint'], env);
    assert.equal(res.status, 500);
    assert.equal((await res.json()).status, 'error');
  }
});

test('an unreachable engine is a 502', async () => {
  // Bind and immediately free a port so nothing is listening on it.
  const probe = createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));

  const res = await call(PUBLIC, ['fingerprint'], {
    VM_ADAPTER_URL: `http://127.0.0.1:${port}`,
    API_KEY: 'k',
  });
  assert.equal(res.status, 502);
  assert.deepEqual(await res.json(), { status: 'error', error: 'analysis engine unreachable' });
});

test('a successful analysis forwards the key and categories and passes findings through', async () => {
  await withFakeAdapter(
    (res) => res.end(JSON.stringify({ status: 'ok', findings: FINDINGS, duration_ms: 12 })),
    async ({ url, seen }) => {
      const res = await call(PUBLIC, ['fingerprint', 'jsBundle'], {
        VM_ADAPTER_URL: url,
        API_KEY: 'secret-key',
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, 'done');
      // Findings must arrive unchanged — the edge is a pass-through, not a
      // re-shaper, and duration_ms (adapter-internal) must not leak into it.
      assert.deepEqual(body.findings, FINDINGS);
      assert.deepEqual(Object.keys(body), ['status', 'findings']);

      assert.equal(seen.length, 1);
      assert.equal(seen[0].method, 'POST');
      assert.equal(seen[0].url, '/analyze');
      assert.equal(seen[0].headers['x-api-key'], 'secret-key');
      assert.deepEqual(seen[0].body.categories, ['fingerprint', 'jsBundle']);
      assert.equal(seen[0].body.url, PUBLIC);
    },
  );
});

test('engine failures map onto the documented public statuses', async () => {
  // DESIGN 5 promises only 200 / 422 / 502 from this route. A 422 keeps its
  // meaning; every other engine failure becomes 502 with the reason intact —
  // notably 401 (adapter key mismatch) must NOT reach the browser as an auth
  // prompt, and a 504 deadline must not widen the contract.
  const cases = [
    [422, 'url blocked: resolves to private IP 10.0.0.5', 422],
    [504, 'analysis exceeded 45000ms', 502],
    [401, 'unauthorised', 502],
    [500, 'internal error: boom', 502],
  ];
  for (const [engineStatus, error, expected] of cases) {
    await withFakeAdapter(
      (res) => {
        res.writeHead(engineStatus, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', error }));
      },
      async ({ url }) => {
        const res = await call(PUBLIC, ['fingerprint'], { VM_ADAPTER_URL: url, API_KEY: 'k' });
        assert.equal(res.status, expected, `engine ${engineStatus} should surface as ${expected}`);
        const body = await res.json();
        // The reason survives regardless of the code it is filed under.
        assert.equal(body.error, error);
      },
    );
  }
});

test('a 2xx carrying an error body is a 502, never a 200', async () => {
  // Contract: HTTP 200 only ever means {status:'done'}. A broken adapter
  // answering 200 {status:'error'} must not be echoed as success.
  await withFakeAdapter(
    (res) => res.end(JSON.stringify({ status: 'error', error: 'internal error: boom' })),
    async ({ url }) => {
      const res = await call(PUBLIC, ['fingerprint'], { VM_ADAPTER_URL: url, API_KEY: 'k' });
      assert.equal(res.status, 502);
      assert.equal((await res.json()).status, 'error');
    },
  );
});

test('a non-object JSON adapter reply is a 502, not a 500 crash', async () => {
  for (const body of ['null', '"just a string"', '42', '{"status":"ok"}', '{"status":"ok","findings":null}']) {
    await withFakeAdapter(
      (res) => res.end(body),
      async ({ url }) => {
        const res = await call(PUBLIC, ['fingerprint'], { VM_ADAPTER_URL: url, API_KEY: 'k' });
        assert.equal(res.status, 502, `body ${body} should map to 502`);
        assert.equal((await res.json()).status, 'error');
      },
    );
  }
});
