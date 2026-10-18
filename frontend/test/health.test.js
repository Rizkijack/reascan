import { test } from 'node:test';
import assert from 'node:assert/strict';

import { onRequestGet, onRequestPost } from '../../functions/api/health.js';

// The route's whole job is a fixed liveness answer; the test pins the exact
// shape so a future edit cannot quietly turn it into a probe with credentials
// or a different contract (README: GET /api/health → 200 { status: "ok" }).
test('health answers 200 with a fixed JSON body', async () => {
  const res = await onRequestGet();
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('health needs no env or request context', async () => {
  // Called with no arguments on purpose: the function must not depend on
  // context, which is what keeps it a pure static answer.
  const res = await onRequestGet();
  assert.equal(res.status, 200);
});

// A wrong method on a known path used to fall through to the static layer and
// answer 200 text/html (the page index); /api/* must stay JSON for every reply.
test('POST on the health route answers 405 JSON', async () => {
  const res = onRequestPost();
  assert.equal(res.status, 405);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await res.json(), { status: 'error', error: 'method not allowed' });
});
