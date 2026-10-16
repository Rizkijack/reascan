import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { findReaBinary, runReaJson, resolveSpawn, _resetBinaryCache } from './reaCli.js';

// The stand-in is a `.mjs` file, not a shell script with a shebang. resolveSpawn
// rewrites any .js/.mjs binary to `node <script>`, so the fixture runs on every
// platform and goes through the same path production takes — these tests cover
// the spawn splice itself, not just the parsing wrapped around it. An earlier
// shebang fixture was skipped on Windows because CreateProcess ignores shebangs,
// which quietly left the most important branch untested on exactly the platform
// that needed it.
function withFakeBin(source, fn) {
  return (async () => {
    const dir = await mkdtemp(join(tmpdir(), 'reascan-fakebin-'));
    const bin = join(dir, 'rea.mjs');
    await writeFile(bin, source);
    const prev = process.env.REA_BIN;
    process.env.REA_BIN = bin;
    _resetBinaryCache();
    try {
      return await fn();
    } finally {
      if (prev === undefined) delete process.env.REA_BIN;
      else process.env.REA_BIN = prev;
      _resetBinaryCache();
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  })();
}

// Emits one complete statement so fixtures can be concatenated; without the
// semicolon `f("a")f("b")` is a syntax error, not two writes.
const say = (obj) => `process.stdout.write(${JSON.stringify(JSON.stringify(obj) + '\n')});`;

test('findReaBinary prefers REA_BIN', async () => {
  await withFakeBin('// fixture\n', async () => {
    assert.match(findReaBinary(), /reascan-fakebin-/);
  });
});

test('runReaJson parses a single JSON object', async () => {
  await withFakeBin(say({ confidence: 'observed' }), async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 15000 });
    assert.equal(result.ok, true);
    assert.equal(result.envelope.confidence, 'observed');
  });
});

test('runReaJson skips JSONL progress lines and takes the final envelope', async () => {
  const script = say({ rea_progress: { phase: 'x' } })
    + say({ normalized_result: { steps: [] }, confidence: 'derived' });
  await withFakeBin(script, async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 15000 });
    assert.equal(result.ok, true);
    assert.equal(result.envelope.confidence, 'derived');
  });
});

test('runReaJson reports unparseable output instead of throwing', async () => {
  await withFakeBin(
    "process.stdout.write('not json at all\\n'); process.exit(1);",
    async () => {
      const result = await runReaJson(['whatever'], { timeoutMs: 15000 });
      assert.equal(result.ok, false);
      assert.match(result.reason, /without parseable JSON/);
    },
  );
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

test('runReaJson times out instead of hanging', async () => {
  await withFakeBin('await new Promise((r) => setTimeout(r, 30000));', async () => {
    const result = await runReaJson(['whatever'], { timeoutMs: 1000 });
    assert.equal(result.ok, false);
    assert.match(result.reason, /timed out/);
  });
});

// --- spawn resolution (Windows portability) ---------------------------------
// reaCli shells out without a shell, so the binary name has to be something
// CreateProcess can start. npm installs only .cmd/.ps1 shims on Windows, which
// spawn() cannot use; the shim's real target is the package's ESM entry, and
// that is what gets executed instead.

test('resolveSpawn runs a JS entry through the current interpreter', () => {
  const entry = 'C:/pkg/rea-agents/scripts/rea.mjs';
  assert.deepEqual(resolveSpawn(entry), { command: process.execPath, prefixArgs: [entry] });
});

test('resolveSpawn leaves a native binary untouched', () => {
  assert.deepEqual(resolveSpawn('/usr/local/bin/rea'), {
    command: '/usr/local/bin/rea',
    prefixArgs: [],
  });
});

test('resolveSpawn honours an explicit REA_BIN verbatim', () => {
  // An operator who names a .cmd shim gets exactly that, not a silent rewrite.
  assert.deepEqual(resolveSpawn('C:/npm/rea.cmd'), {
    command: 'C:/npm/rea.cmd',
    prefixArgs: [],
  });
});

test('resolveSpawn falls back to the bare name when no package entry exists', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'reascan-empty-path-'));
  const prev = process.env.PATH;
  process.env.PATH = dir;
  try {
    assert.deepEqual(resolveSpawn('rea'), { command: 'rea', prefixArgs: [] });
  } finally {
    if (prev === undefined) delete process.env.PATH;
    else process.env.PATH = prev;
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

// PATH entries containing spaces are commonly stored quoted on Windows. The
// quotes are a REG_EXPAND_SZ artefact, not part of the path; treating them as
// part of it produced a miss that looked exactly like "REA is not installed".
test('resolveSpawn resolves a quoted PATH entry', {
  skip: process.platform === 'win32' ? false : 'Windows-only PATH quoting',
}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'reascan-quoted-path-'));
  const scripts = join(dir, 'node_modules', 'rea-agents', 'scripts');
  await mkdir(scripts, { recursive: true });
  await writeFile(join(scripts, 'rea.mjs'), '// fixture\n');

  const prev = process.env.PATH;
  process.env.PATH = `"${dir}"`;
  try {
    assert.deepEqual(resolveSpawn('rea'), {
      command: process.execPath,
      prefixArgs: [join(scripts, 'rea.mjs')],
    });
  } finally {
    if (prev === undefined) delete process.env.PATH;
    else process.env.PATH = prev;
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('resolveSpawn maps the bare rea name to the package entry on Windows', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'reascan-path-'));
  const scripts = join(dir, 'node_modules', 'rea-agents', 'scripts');
  await mkdir(scripts, { recursive: true });
  await writeFile(join(scripts, 'rea.mjs'), '// fixture\n');

  const prev = process.env.PATH;
  process.env.PATH = dir;
  try {
    if (process.platform === 'win32') {
      assert.deepEqual(resolveSpawn('rea'), {
        command: process.execPath,
        prefixArgs: [join(scripts, 'rea.mjs')],
      });
    } else {
      // POSIX resolves the bare name from PATH at exec time; nothing to rewrite.
      assert.deepEqual(resolveSpawn('rea'), { command: 'rea', prefixArgs: [] });
    }
  } finally {
    if (prev === undefined) delete process.env.PATH;
    else process.env.PATH = prev;
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});