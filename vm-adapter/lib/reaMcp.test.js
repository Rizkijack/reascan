import { test } from 'node:test';
import assert from 'node:assert/strict';

import { callReaTool, REA_MCP_ENABLED, REA_TOOLS } from './reaMcp.js';

// The stub is a placeholder, not a silent success. If a category ever reaches
// it, the caller must get a degradable failure — an {ok:true} here would make
// the adapter claim work it never did.
test('callReaTool fails with a reason instead of throwing', async () => {
  const result = await callReaTool('asar.extract', { path: '/tmp/app.asar' });
  assert.equal(result.ok, false);
  assert.match(result.reason, /phase 2/);
});

test('the MVP stub stays disabled', () => {
  assert.equal(REA_MCP_ENABLED, false);
});

test('the tool list is declared data', () => {
  assert.ok(Array.isArray(REA_TOOLS));
  assert.ok(REA_TOOLS.every((t) => typeof t === 'string' && t.includes('.')));
});
