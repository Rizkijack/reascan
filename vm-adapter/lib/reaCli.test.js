import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { findReaBinary, runReaJson, resolveSpawn, _resetBinaryCache, analyzeJsDeep } from './reaCli.js';

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

// --- deep JS analysis budget -------------------------------------------------
// server.js races every category against one 70s deadline, so `timeoutMs` here
// is the budget for the WHOLE category — the page fetch and the bundle downloads
// included. Handing REA a fresh full-length timeout after those phases had
// already spent most of the budget let the call run past that deadline, and the
// rejected Promise.race 504'd the entire report rather than one category. These
// tests pin the budget to the whole call.

// Shaped exactly like urlGuard.safeFetch's return value, so analyzeJsDeep takes
// the same branch it takes in production with no real network traffic. Every call
// is recorded with the timeout it was handed, because the budget is what these
// tests assert on: a wall-clock bound would be the one thing on this path able to
// flake on a loaded box, while the recorded timeouts are exact.
function fakeSite({ bundleDelayMs = 0, bundles = 5 } = {}) {
  const html = `<html><head>${Array.from({ length: bundles }, (_, i) =>
    `<script src="https://cdn.example/b${i}.js"></script>`).join('')}</head></html>`;
  const calls = [];
  const safeFetch = async (target, opts) => {
    const url = String(target?.url ?? target);
    const isBundle = url.includes('cdn.example');
    calls.push({ url, timeoutMs: opts?.timeoutMs, isBundle });
    if (isBundle) await new Promise((r) => setTimeout(r, bundleDelayMs));
    const text = isBundle ? 'var a = 1;' : html;
    async function* body() { yield Buffer.from(text); }
    return { ok: true, finalUrl: url, response: { ok: true, status: 200, body: body() } };
  };
  return { safeFetch, calls, bundleCalls: () => calls.filter((c) => c.isBundle) };
}

test('analyzeJsDeep charges bundle downloads against the budget it was given', async () => {
  const budget = 1000;
  const { safeFetch, calls, bundleCalls } = fakeSite({ bundleDelayMs: 400 });
  const result = await analyzeJsDeep('https://example.com/', safeFetch, { timeoutMs: budget });

  assert.equal(result.ok, false);
  assert.match(result.reason, /budget/);
  // The limitation is shown to whoever scanned the URL; the temp dir holds the
  // target's own downloaded code and stays on the VM.
  assert.ok(!/reascan-jsdeep|[\\/]/.test(result.reason), `reason leaks a path: ${result.reason}`);

  // Five 400ms bundles cannot fit a 1000ms budget, so the loop stops on the clock
  // rather than running the list out. Timers never fire early, so a slow box only
  // makes this shorter — the bound cannot invert under load.
  assert.ok(bundleCalls().length < 5, `attempted ${bundleCalls().length} bundles`);

  // Both phases are charged. Before the fix every fetch got a fresh 10000ms.
  assert.ok(calls.every((c) => c.timeoutMs > 0 && c.timeoutMs <= budget),
    `unbudgeted fetch: ${JSON.stringify(calls)}`);

  // The budget only ever shrinks, so REA inherits whatever is left.
  const granted = calls.map((c) => c.timeoutMs);
  assert.deepEqual(granted, [...granted].sort((a, b) => b - a), `budget grew: ${JSON.stringify(granted)}`);
});

test('analyzeJsDeep hands REA only the budget the downloads left, not a fresh one', async () => {
  // The subprocess deadline is the other end of the same bug: a full-length
  // timeout here is what let the call outlive server.js's Promise.race. With one
  // instant download the leftover is the budget minus a few milliseconds, so the
  // timeout quoted in the failure is the number this pins — strictly below the
  // budget on the fixed path, exactly equal to it on the old one.
  await withFakeBin('await new Promise((r) => setTimeout(r, 4000));', async () => {
    const budget = 500;
    // One bundle on purpose: the lower bound below is the only wall-clock value
    // left in this file, and a single fetch cannot eat enough of the budget to
    // trip it on a loaded box the way five fetches could.
    const { safeFetch } = fakeSite({ bundles: 1 });
    const result = await analyzeJsDeep('https://example.com/', safeFetch, { timeoutMs: budget });

    assert.equal(result.ok, false);
    const granted = /timed out after (\d+)ms/.exec(result.reason)?.[1];
    assert.ok(granted, `expected a REA timeout, got: ${result.reason}`);
    assert.ok(Number(granted) < budget, `REA was granted the full ${budget}ms budget, not the remainder`);
    assert.ok(Number(granted) >= 150, `REA was left a degenerate ${granted}ms`);
  });
});

test('analyzeJsDeep removes its temp dir when the budget runs out before REA', async () => {
  // This return path is new — the guard that skips the subprocess has no other
  // test on it, and the bundles written so far are the target's own code.
  //
  // os.tmpdir() re-reads the environment on every call, so pointing it at a
  // directory of this test's own is what makes the assertion sound: node --test
  // runs files in parallel processes, and a readdir diff against the shared
  // system temp dir sees another process's reascan-jsdeep-* as this one's leak.
  const sandbox = await mkdtemp(join(tmpdir(), 'reascan-tmproot-'));
  const prev = {};
  for (const key of ['TMPDIR', 'TEMP', 'TMP']) {
    prev[key] = process.env[key];
    process.env[key] = sandbox;
  }
  try {
    const { safeFetch } = fakeSite({ bundleDelayMs: 400 });
    const result = await analyzeJsDeep('https://example.com/', safeFetch, { timeoutMs: 1000 });
    assert.equal(result.ok, false);

    const left = (await readdir(sandbox)).filter((n) => n.startsWith('reascan-jsdeep-'));
    assert.deepEqual(left, [], `temp dirs left behind: ${left.join(', ')}`);
  } finally {
    for (const key of ['TMPDIR', 'TEMP', 'TMP']) {
      if (prev[key] === undefined) delete process.env[key];
      else process.env[key] = prev[key];
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => {});
  }
});

test('analyzeJsDeep still runs REA when the downloads leave budget for it', async () => {
  await withFakeBin(
    say({ normalized_result: { statistics: { modules: 3, findings: 7, visited_ast_nodes: 42 } }, confidence: 'derived' }),
    async () => {
      const { safeFetch, bundleCalls } = fakeSite();
      const result = await analyzeJsDeep('https://example.com/', safeFetch, { timeoutMs: 30000 });
      assert.equal(result.ok, true);
      assert.equal(bundleCalls().length, 5);
      assert.equal(result.analysis.files_analysed, 5);
      assert.equal(result.analysis.findings, 7);
    },
  );
});
