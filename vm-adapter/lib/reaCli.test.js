import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { findReaBinary, runReaJson, _resetBinaryCache } from './reaCli.js';

function withFakeBin(script, fn) {
  return (async () => {
    const dir = await mkdtemp(join(tmpdir(), 'reascan-fakebin-'));
    const bin = join(dir, 'rea');
    await writeFile(bin, script);
    await chmod(bin, 0o755);
    const prev = process.env.REA_BIN;
    process.env.REA_BIN = bin;
    _resetBinaryCache();
    try {
      return await fn();
    } finally {
      if (prev === undefined) delete process.env.REA_BIN;
      else process.env.REA_BIN = prev;
      _resetBinaryCache();
    }
  })();
}

// The fixture below is a POSIX shell script. Windows CreateProcess does not honour
// a shebang, and reaCli spawns without a shell, so the stand-in binary cannot be
// executed there at all (ENOENT). The logic under test is platform-independent but
// the fixture is not: these four run on the VM, which is where `rea` actually lives.
// Skipped explicitly with a reason rather than deleted, so the coverage comes back
// on any POSIX host and the gap is visible in the report instead of silent.
const needsPosix = process.platform === 'win32'
  ? { skip: 'fixture is a POSIX shell script; Windows spawn cannot execute it' }
  : {};

test('findReaBinary prefers REA_BIN', async () => {
  await withFakeBin('#!/bin/sh\necho {}', async () => {
    assert.match(findReaBinary(), /reascan-fakebin-/);
  });
});

test('runReaJson parses a single JSON object', needsPosix, async () => {
  await withFakeBin('#!/bin/sh\necho \'{"confidence":"observed"}\'', async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 5000 });
    assert.equal(result.ok, true);
    assert.equal(result.envelope.confidence, 'observed');
  });
});

test('runReaJson skips JSONL progress lines and takes the final envelope', needsPosix, async () => {
  const script = '#!/bin/sh\n'
    + 'echo \'{"rea_progress":{"phase":"x"}}\'\n'
    + 'echo \'{"normalized_result":{"steps":[]},"confidence":"derived"}\'';
  await withFakeBin(script, async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 5000 });
    assert.equal(result.ok, true);
    assert.equal(result.envelope.confidence, 'derived');
  });
});

test('runReaJson reports unparseable output instead of throwing', needsPosix, async () => {
  await withFakeBin('#!/bin/sh\necho "not json at all"\nexit 1', async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 5000 });
    assert.equal(result.ok, false);
    assert.match(result.reason, /without parseable JSON/);
  });
});

test('runReaJson reports a missing binary instead of throwing', async () => {
  const prev = process.env.REA_BIN;
  process.env.REA_BIN = '/nonexistent/path/to/rea';
  _resetBinaryCache();
  try {
    const result = await runReaJson(['whatever'], { timeoutMs: 5000 });
    assert.equal(result.ok, false);
    assert.match(result.reason, /not runnable|without parseable JSON/);
  } finally {
    if (prev === undefined) delete process.env.REA_BIN;
    else process.env.REA_BIN = prev;
    _resetBinaryCache();
  }
});

test('runReaJson times out instead of hanging', needsPosix, async () => {
  await withFakeBin('#!/bin/sh\nsleep 30', async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 1000 });
    assert.equal(result.ok, false);
    assert.match(result.reason, /timed out/);
  });
});
