import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { findReaBinary, runReaJson, resolveSpawn, _resetBinaryCache, analyzeJsDeep, inspectWebPage } from './reaCli.js';

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

// --- web inspect -------------------------------------------------------------
// One fake binary serves all four sub-invocations (inspect / listeners /
// webmcp / export), keyed on the sub-command exactly as the real CLI reads
// its argv. The browser env is injected, so no browser is anywhere near the
// box and every path here is offline.

const INSPECT_ENVELOPE = {
  normalized_result: {
    target: { target_id: 'tid', title: 'Example', url: 'https://example.com/', origin: 'https://example.com' },
    scripts: {
      total: 2,
      items: [
        {
          script_key: 'k1', url: 'https://example.com/s.js', origin: 'https://example.com',
          cdp_hash: 'aa11bb22', length: 1579, is_module: false, source_map_url: null,
          // In production this field is the script's full text. Its presence
          // here is the point: the distiller must not copy it into the payload.
          source: { included: true, artifact: { sha256: 'aa11bb22', RETAINED_SOURCE_MARKER: 'NEVER SHIP THIS' } },
        },
        { script_key: 'k2', url: 'https://cdn.example/tracker.js', origin: 'https://cdn.example', cdp_hash: 'cc33', length: 10, is_module: true, source_map_url: 'https://cdn.example/tracker.js.map' },
      ],
    },
    resources: [{ type: 'Script' }, { type: 'Script' }, { type: 'Document' }],
    network: { requests: [] },
    console: { events: [] },
    workers: [],
    metadata: {
      dom_urls: [
        { node_index: 1, attribute: 'href', url: 'https://example.com/help', destination_scope: 'approved' },
        { node_index: 2, attribute: 'href', url: 'https://analytics.example/px', destination_scope: 'outside_policy' },
      ],
    },
    storage: { origin: 'https://example.com', usage_bytes: 0, quota_bytes: 42, local_storage_keys: ['layout'], values_redacted: true },
    limitations: ['Observation starts when REA attaches; prior activity is unavailable.'],
  },
  confidence: 'observed',
};

const LISTENERS_ENVELOPE = {
  normalized_result: {
    selected_node: { match: 'found' },
    listeners: [
      { type: 'click', location: { script_id: '52', url: 'https://cdn.example/framework.js', line_number: 3, column_number: 4251 } },
      { type: 'submit', location: { url: 'https://cdn.example/second.js', line_number: 9, column_number: 2 } },
    ],
  },
  confidence: 'observed',
};

const WEBMCP_ENVELOPE = {
  normalized_result: { status: 'available', tools: { total: 1, items: [{ name: 'page.search' }] } },
  confidence: 'observed',
};

const EXPORT_ENVELOPE = {
  normalized_result: {
    scripts: [{ url: 'https://example.com/s.js', content: { state: 'exported', sha256: 'aa11bb22', bytes: 1579 } }],
  },
  confidence: 'derived',
};

// overwrite: the same envelope dictionary with the sub-command's answer swapped
// out, so one fixture file can serve several expected shapes per test.
function webInspectFixture(overrides = {}) {
  const envelopes = {
    'inspect-web-page': INSPECT_ENVELOPE,
    'inspect-web-event-listeners': LISTENERS_ENVELOPE,
    'discover-webmcp-tools': WEBMCP_ENVELOPE,
    'export-web-scripts': EXPORT_ENVELOPE,
    ...overrides,
  };
  return `
    const args = process.argv.slice(2);
    const printed = JSON.parse(${JSON.stringify(JSON.stringify(envelopes))});
    const key = Object.keys(printed).find((k) => args.includes(k));
    let envelope = printed[key];
    if (key === 'export-web-scripts') {
      const fs = await import('node:fs/promises');
      try {
        const text = await fs.readFile(args[args.indexOf('export-web-scripts') + 1], 'utf8');
        if (!text.includes('RETAINED_SOURCE_MARKER') || !text.includes('normalized_result')) {
          envelope = { error: 'fixture: capture file incomplete' };
        }
      } catch {
        envelope = { error: 'fixture: no capture file' };
      }
    }
    process.stdout.write(JSON.stringify(envelope) + '\\n');
  `;
}

const fakeBrowserEnv = () => async () => ({ ok: true, cdpEndpoint: 'http://cdp.test', targetId: 'tid' });

test('inspectWebPage distils the four CLI invocations into the evidence shape', async () => {
  await withFakeBin(webInspectFixture(), async () => {
    const result = await inspectWebPage('https://example.com/', undefined, {
      timeoutMs: 30000,
      browserEnv: fakeBrowserEnv(),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    const wi = result.inspection;

    assert.equal(wi.scripts_total, 2);
    assert.equal(wi.scripts.length, 2);
    assert.equal(wi.scripts[0].source_digest, 'aa11bb22', 'export verifies and replaces the inventory digest');
    assert.equal(wi.scripts[1].is_module, true);
    assert.equal(wi.exported_scripts, 1);
    assert.deepEqual(wi.script_domain_counts, { 'example.com': 1, 'cdn.example': 1 });
    assert.deepEqual(wi.resource_type_counts, { Script: 2, Document: 1 });
    assert.deepEqual(wi.event_listeners, [
      { type: 'click', url: 'https://cdn.example/framework.js', line: 3, column: 4251 },
      { type: 'submit', url: 'https://cdn.example/second.js', line: 9, column: 2 },
    ]);
    assert.deepEqual(wi.webmcp_tools, [{ name: 'page.search', declared: true }]);
    assert.deepEqual(wi.third_party.third_party_domains.sort(), ['analytics.example', 'cdn.example']);
    assert.deepEqual(wi.third_party.outside_policy_dom_urls, ['https://analytics.example/px']);
    assert.equal(wi.storage.has_keys, true);
    assert.equal(wi.storage.usage_bytes, 0);
    assert.equal(wi.workers, 0);
    assert.equal(wi.target.url, 'https://example.com/');
    assert.ok(wi.limitations.some((l) => /Observation starts when REA attaches/.test(l)));

    // The retained source text stayed in the temp capture the CLI read; the
    // payload carries digests, never the text itself.
    assert.ok(!JSON.stringify(result).includes('NEVER SHIP THIS'),
      'no source text may cross the boundary: this is the point of the distillation');
    // Every failure path stayed a limitation, none threw across the boundary.
    assert.ok(!/score|percentage/.test(JSON.stringify(wi)), 'the evidence standard carries no numeric verdicts');
  });
});

test('inspectWebPage charges the env, the inspect, and every sub-call against one budget', async () => {
  // The wall-clock check at the parse boundary: the listeners subprocess gets
  // whatever the inspect phase left, never a fresh full-length timeout. The
  // inspect answer returns instantly so a measurable amount of the budget is
  // genuinely spent before the second phase - with a sleeping first phase the
  // remainder equals the budget and the fresh-vs-remainder bug is invisible.
  const budgetFixture = `
    const args = process.argv.slice(2);
    if (args.includes('inspect-web-page')) {
      process.stdout.write(JSON.stringify(JSON.parse(${JSON.stringify(JSON.stringify(INSPECT_ENVELOPE))})) + '\\n');
    } else {
      // every other sub-command prints nothing and never exits, so the only
      // way this command ends is reaCli's own deadline (SIGKILL)
      setInterval(() => {}, 1e6);
    }
  `;
  await withFakeBin(budgetFixture, async () => {
    // 5000 not 500: after the instant inspect answer the listeners probe must
    // still be granted the real remainder (~4950ms), while a fresh full-length
    // allowance (the bug) would be 5000. The 50ms margin comes from the spawn
    // itself, so the bound cannot invert under load.
    const budget = 5000;
    const result = await inspectWebPage('https://example.com/', undefined, {
      timeoutMs: budget,
      browserEnv: fakeBrowserEnv(),
    });
    assert.equal(result.ok, true);
    const granted = /inspect-web-event-listeners failed: .*timed out after (\d+)ms/.exec(
      result.inspection.limitations.join(' '),
    )?.[1];
    assert.ok(granted, `expected the listeners probe to record its timeout, got: ${JSON.stringify(result.inspection.limitations)}`);
    assert.ok(Number(granted) < budget, `the listeners probe got a fresh ${budget}ms allowance instead of the remainder`);
    assert.ok(Number(granted) >= 150, `the listeners probe was left a degenerate ${granted}ms`);
  });
});

test('a refused sub-call is a named limitation, not a discarded category', async () => {
  await withFakeBin(webInspectFixture({
    'inspect-web-event-listeners': { error: 'engine refused the listener probe' },
    'discover-webmcp-tools': { error: 'engine refused the webmcp probe' },
  }), async () => {
    const result = await inspectWebPage('https://example.com/', undefined, {
      timeoutMs: 30000,
      browserEnv: fakeBrowserEnv(),
    });
    assert.equal(result.ok, true);
    assert.deepEqual(result.inspection.event_listeners, []);
    assert.deepEqual(result.inspection.webmcp_tools, []);
    assert.ok(result.inspection.limitations.some((l) => l.includes('inspect-web-event-listeners failed: engine refused the listener probe')),
      JSON.stringify(result.inspection.limitations));
    assert.ok(result.inspection.limitations.some((l) => l.includes('discover-webmcp-tools failed: engine refused the webmcp probe')),
      JSON.stringify(result.inspection.limitations));
  });
});

test('the export scratch dir is removed even when export fails', {
  // os.tmpdir() re-reads env per call, so a sandbox root keeps the leak check
  // hermetic against parallel node --test processes.
}, async () => {
  const sandbox = await mkdtemp(join(tmpdir(), 'reascan-tmproot-'));
  const prev = {};
  for (const key of ['TMPDIR', 'TEMP', 'TMP']) {
    prev[key] = process.env[key];
    process.env[key] = sandbox;
  }
  try {
    await withFakeBin(webInspectFixture({
      'export-web-scripts': { error: 'persistently refusing engine' },
    }), async () => {
      const result = await inspectWebPage('https://example.com/', undefined, {
        timeoutMs: 30000,
        browserEnv: fakeBrowserEnv(),
      });
      assert.equal(result.ok, true);
      assert.ok(result.inspection.limitations.some((l) => /export-web-scripts failed/.test(l)),
        JSON.stringify(result.inspection.limitations));
      const left = (await readdir(sandbox)).filter((n) => n.startsWith('reascan-webinspect-'));
      assert.deepEqual(left, [], `temp dirs left behind: ${left.join(', ')}`);
    });
  } finally {
    for (const key of ['TMPDIR', 'TEMP', 'TMP']) {
      if (prev[key] === undefined) delete process.env[key];
      else process.env[key] = prev[key];
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => {});
  }
});

test('a browser env that cannot come up is a reason, never an unhandled throw', async () => {
  const result = await inspectWebPage('https://example.com/', undefined, {
    timeoutMs: 5000,
    browserEnv: async () => ({ ok: false, reason: 'the capture env refused to assemble' }),
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /capture env refused to assemble/);
});

test('inspectWebPage refuses a URL without an origin before touching the browser', async () => {
  const result = await inspectWebPage('not a url at all', undefined, { timeoutMs: 5000, browserEnv: fakeBrowserEnv() });
  assert.equal(result.ok, false);
  assert.match(result.reason, /absolute/);
  assert.ok(!/score/.test(result.reason), 'no numeric verdicts, even in rejections');
});

// The listeners budget pin proves the mechanism; this one follows the chain one
// probe further. A sub-call failing early must hand the NEXT probe the budget
// the failure left — and once the deadline runs out mid-stream, everything after
// degrades to named limitations with the category still ok:true. A 504 here
// would cost the caller every other category in the same report.
test('a consumed budget degrades the remaining probes to named limitations, never a 504', async () => {
  // inspect answers instantly; listeners burns a scheduled ~400ms then fails;
  // webmcp never exits, so its only way out is reaCli's own deadline.
  const stageFixture = () => `
    const args = process.argv.slice(2);
    if (args.includes('inspect-web-page')) {
      process.stdout.write(JSON.stringify(JSON.parse(${JSON.stringify(JSON.stringify(INSPECT_ENVELOPE))})) + '\\n');
    } else if (args.includes('inspect-web-event-listeners')) {
      await new Promise((resolve) => setTimeout(resolve, 400));
      process.stdout.write(JSON.stringify({ error: 'fixture: listeners died on schedule' }) + '\\n');
    } else {
      setInterval(() => {}, 1e6);
    }
  `;
  await withFakeBin(stageFixture(), async () => {
    const budget = 6000;
    const result = await inspectWebPage('https://example.com/', undefined, {
      timeoutMs: budget,
      browserEnv: fakeBrowserEnv(),
    });
    // The category must ride out the exhausted budget: ok:true, with an
    // explicit record of everything that was skipped, nothing thrown. THIS
    // is the anti-504 pin.
    assert.equal(result.ok, true, JSON.stringify(result).slice(0, 400));
    const limits = result.inspection.limitations.join(' ');

    assert.ok(limits.includes('inspect-web-event-listeners failed: fixture: listeners died on schedule'),
      `listeners failure must be recorded as its own limitation, got: ${limits}`);

    // The webmcp probe is granted what the failed listeners probe left - a
    // fresh full allowance would read "timed out after 6000ms".
    const granted = /discover-webmcp-tools failed: .*timed out after (\d+)ms/.exec(limits)?.[1];
    assert.ok(granted, `expected the webmcp probe to testify its own timeout, got: ${limits}`);
    assert.ok(Number(granted) < budget, `the webmcp probe got a fresh ${budget}ms allowance instead of the remainder`);
    assert.ok(Number(granted) >= 4000, `the webmcp probe was left a degenerate ${granted}ms`);

    // After the deadline is gone, the export is skipped by the budget gate -
    // and the skip must say so in the verbiage, not vanish.
    assert.equal(result.inspection.exported_scripts, null);
    assert.ok(/script export skipped: not enough budget left \(\d+ms held\)/.test(limits),
      `expected an explicit export skip limitation, got: ${limits}`);
    assert.deepEqual(result.inspection.webmcp_tools, [], 'a skipped probe leaves the section empty, not raw data');
  });
});

// The distiller holds an allow-list of copied fields (smoke pins the shape
// statically); this test pins it behaviorally: every channel a passive
// inspection could spill - script source text, storage values AND key names,
// cookies, console text, DOM text, arbitrary metadata fields, and any "score"
// field - is poisoned in the fixture, and every marker must be kept out of
// the payload. The payload size is asserted too: a leak shows up as bulk
// before individual marker checks would.
test('every narrative channel of the inspection envelope is locked out of the payload', async () => {
  const POISON_20KB = 'RETAINED_SOURCE_MARKER ' + 'x'.repeat(20480) + ' POISON_TAIL';
  const POISONED_ENVELOPE = {
    normalized_result: {
      target: { target_id: 'tid', title: 'Poison Example', url: 'https://example.com/', origin: 'https://example.com' },
      scripts: {
        total: 1,
        items: [{
          script_key: 'k1', url: 'https://example.com/s.js', origin: 'https://example.com',
          cdp_hash: 'aa11bb22', length: POISON_20KB.length, is_module: false, source_map_url: null,
          source: { included: true, artifact: { sha256: 'aa11bb22', text: POISON_20KB } },
          rendered_size_bytes: POISON_20KB.length,
        }],
      },
      resources: [{ type: 'Script' }],
      network: { requests: [] },
      workers: [],
      cookies: [{ name: 'sid', value: 'POISON_COOKIE_VALUE' }],
      console: { events: [{ text: 'POISON_CONSOLE_TEXT secret=1' }, { text: 'second line' }] },
      metadata: {
        dom_urls: [{ node_index: 1, attribute: 'href', url: 'https://example.com/help', destination_scope: 'approved' }],
        dom_nodes: [{ node_index: 2, text: 'POISON_DOM_TEXT' }],
        page_audit_notes: 'POISON_METADATA_TEXT',
      },
      storage: {
        origin: 'https://example.com', usage_bytes: 1234, quota_bytes: 9999,
        local_storage_keys: ['layout', 'POISON_STORAGE_KEY'],
        local_storage_values: [{ key: 'layout', value: 'POISON_STORAGE_VALUE' }],
        cookies_storage: [{ name: 'sid', value: 'POISON_COOKIE_VALUE' }],
        values_redacted: false,
      },
      score: 'POISON_GRADE',
      normalized_partial_score: 42,
      limitations: ['Observation starts when REA attaches; prior activity is unavailable.'],
    },
    confidence: 'observed',
  };
  await withFakeBin(webInspectFixture({ 'inspect-web-page': POISONED_ENVELOPE }), async () => {
    const result = await inspectWebPage('https://example.com/', undefined, {
      timeoutMs: 30000,
      browserEnv: fakeBrowserEnv(),
    });
    assert.equal(result.ok, true, JSON.stringify(result).slice(0, 400));
    const payload = JSON.stringify(result);

    for (const marker of [
      'RETAINED_SOURCE_MARKER', 'POISON_TAIL',
      'POISON_STORAGE_VALUE', 'POISON_STORAGE_KEY',
      'POISON_COOKIE_VALUE', 'POISON_CONSOLE_TEXT',
      'POISON_DOM_TEXT', 'POISON_METADATA_TEXT', 'POISON_GRADE',
    ]) {
      assert.ok(!payload.includes(marker), `leak: "${marker}" crossed the distillation boundary — ${payload.slice(0, 300)}`);
    }
    assert.ok(!/"score"/.test(payload), 'no score field of any shape may appear in the payload');

    // Presence evidence survives without the underlying material.
    const wi = result.inspection;
    assert.equal(wi.storage.has_keys, true, 'key PRESENCE is the evidence, not the material');
    assert.deepEqual(Object.keys(wi.storage).sort(),
      ['has_keys', 'origin', 'quota_bytes', 'usage_bytes'], 'storage ships only enumerated fields');
    assert.equal(wi.console_events, 2, 'console is evidence as a COUNT only');
    assert.equal(wi.scripts[0].length, POISON_20KB.length, 'byte size is evidence, bytes are not');

    // A leak shows up as bulk long before a named marker check would catch:
    // the distilled payload for one script must stay in the kilobytes.
    assert.ok(payload.length < 6000, `payload of ${payload.length} bytes for one script smells like a leak`);
  });
});
