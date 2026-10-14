import { test } from 'node:test';
import assert from 'node:assert/strict';

import { onRequestPost } from '../../functions/api/analyze.js';
import { createAdapter } from '../../vm-adapter/server.js';

// Whole-tree contract test: the REAL Pages Function against the REAL adapter.
// Every other edge test uses a fake engine, so nothing else exercises the two
// halves together — and the defects the step-7 audit hunted for lived exactly on
// this seam (a 2xx error body echoed as 200; engine statuses widening the public
// contract). Cross-tree import is deliberate: the thing under test IS the seam.

const KEY = 'integration-key-0123456789ab';

async function withAdapter(run) {
  const server = createAdapter({ API_KEY: KEY });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const callEdge = (env, body) =>
  onRequestPost({
    request: new Request('https://reascan.pages.dev/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env,
  });

test('a real adapter 401 surfaces as 502, not as an auth prompt', async () => {
  await withAdapter(async (base) => {
    const res = await callEdge(
      { VM_ADAPTER_URL: base, API_KEY: 'wrong-key-value-000000000' },
      { url: 'http://93.184.216.34/', categories: ['fingerprint'] },
    );
    assert.equal(res.status, 502);
    // The reason survives the remap.
    assert.equal((await res.json()).error, 'unauthorised');
  });
});

test('the adapter refuses an unauthenticated health check', async () => {
  await withAdapter(async (base) => {
    assert.equal((await fetch(`${base}/health`)).status, 401);
    const ok = await fetch(`${base}/health`, { headers: { 'x-api-key': KEY } });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), {
      status: 'ok',
      tools_available: ['fingerprint', 'jsBundle', 'browserCapture', 'jsDeep'],
      rea_tools: ['browser.capture', 'js.analyzeDeep'],
    });
  });
});

test('edge -> real adapter -> target never widens the documented contract', async () => {
  // Reaches a live public target, so this is the network-touching test of the
  // trio (same precedent as vm-adapter/server.test.js). A dead target still
  // yields a structured report — failures go into limitations — so the shape
  // assertions hold whether or not the fetch succeeds.
  await withAdapter(async (base) => {
    const res = await callEdge(
      { VM_ADAPTER_URL: base, API_KEY: KEY },
      { url: 'https://example.com/', categories: ['fingerprint', 'jsBundle'] },
    );
    const body = await res.json();

    assert.ok([200, 502].includes(res.status), `unexpected status ${res.status}`);
    if (res.status !== 200) return;

    assert.equal(body.status, 'done');
    const f = body.findings;
    assert.ok(Array.isArray(f.fingerprint.findings));
    assert.ok(Array.isArray(f.js_bundles));
    assert.ok(Array.isArray(f.verdict.limitations));
    assert.ok(Array.isArray(f.verdict.unknowns));
    assert.ok(['high', 'medium', 'low'].includes(f.verdict.confidence));

    // Evidence standard: every finding carries its provenance and a rank, and
    // types stay inside the three allowed values.
    for (const finding of f.fingerprint.findings) {
      assert.ok(finding.key && finding.value !== undefined);
      assert.ok(finding.evidence, 'a finding without evidence is not a finding');
      assert.ok(['observation', 'derivation', 'inference'].includes(finding.type));
      assert.ok(['high', 'medium', 'low'].includes(finding.confidence));
    }

    // Not a numeric score, and never a secret value (no secret-pattern detection).
    assert.ok(!JSON.stringify(f).toLowerCase().includes('score'));
    assert.ok(!JSON.stringify(f).toLowerCase().includes('secret'));
  });
});
