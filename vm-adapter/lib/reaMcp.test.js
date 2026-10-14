import { test } from 'node:test';
import assert from 'node:assert/strict';

import { callReaTool, REA_MCP_ENABLED, REA_TOOLS } from './reaMcp.js';

// The integration contract: a dispatch never throws and never claims work it
// did not do. Unknown tools, missing args, and engines absent from the VM all
// answer {ok:false, reason} so the caller can degrade them to limitations.
test('the REA integration is enabled', () => {
  assert.equal(REA_MCP_ENABLED, true);
});

test('the tool list is declared data', () => {
  assert.ok(Array.isArray(REA_TOOLS));
  assert.ok(REA_TOOLS.every((t) => typeof t === 'string' && t.includes('.')));
  assert.ok(REA_TOOLS.includes('browser.capture'));
  assert.ok(REA_TOOLS.includes('js.analyzeDeep'));
});

test('unknown tool fails with a reason instead of throwing', async () => {
  const result = await callReaTool('nope.nothing', { url: 'https://example.com/' });
  assert.equal(result.ok, false);
  assert.match(result.reason, /unknown REA tool/);
});

test('missing url fails with a reason instead of throwing', async () => {
  const result = await callReaTool('browser.capture', {});
  assert.equal(result.ok, false);
  assert.match(result.reason, /args\.url/);
});

test('js.analyzeDeep without safeFetch fails with a reason', async () => {
  const result = await callReaTool('js.analyzeDeep', { url: 'https://example.com/' });
  assert.equal(result.ok, false);
  assert.match(result.reason, /safeFetch/);
});

test('uninstalled engine categories degrade with a reason', async () => {
  for (const tool of ['asar.extract', 'ghidra.analyzeHeadless', 'apktool.decode']) {
    const result = await callReaTool(tool, { url: 'https://example.com/' });
    assert.equal(result.ok, false);
    assert.match(result.reason, /not installed/);
  }
});
