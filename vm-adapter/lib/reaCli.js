// REA backend client for the reascan adapter.
//
// This is the phase-2 integration point: the adapter shells out to the `rea`
// CLI installed on the VM (zero new npm dependencies — Node built-ins only,
// matching the adapter's existing philosophy). Every function answers
// {ok:true, ...} | {ok:false, reason} so a missing binary, a timeout, or a
// target the engine cannot handle degrades to a limitation instead of throwing
// across the HTTP boundary.
//
// Verified against rea v6.4.0 on this VM:
//   - capture-browser-scenario  (needs the reaEnv browser prerequisites)
//   - analyze-javascript-application
// Native/APK/.NET categories are intentionally NOT wired: they need
// Hopper/Ghidra/IDA, JADX/JDK, or ilspycmd, none of which is installed.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';

let cachedBin = null;

// Resolve the rea binary. REA_BIN wins (systemd unit / .env), then PATH,
// then the conventional user-local install. Cached after first lookup.
export function findReaBinary() {
  if (cachedBin) return cachedBin;
  if (process.env.REA_BIN) {
    cachedBin = process.env.REA_BIN;
    return cachedBin;
  }
  cachedBin = 'rea';
  return cachedBin;
}

// Test hook: forget the cached lookup (tests must not leak env between cases).
export function _resetBinaryCache() {
  cachedBin = null;
}

// Turn a configured binary name into something spawn() can actually start.
//
// On POSIX `rea` is a real executable and the name passes through untouched.
// On Windows npm writes only `rea.cmd`/`rea.ps1` shims: spawn() resolves neither
// (ENOENT — Node does not walk PATHEXT) and refuses .cmd outright without a
// shell (EINVAL). Those shims are generated wrappers that end in the package's
// own ESM entry, so we invoke that script with the interpreter already running
// us. This is what the shim does, minus the shell — no shell:true, no quoting,
// no way for an argument to become shell syntax.
export function resolveSpawn(bin) {
  if (/\.m?js$/i.test(bin)) return { command: process.execPath, prefixArgs: [bin] };

  // Only for the implicit PATH lookup. An explicit REA_BIN is the operator's
  // chosen command and is left alone; REA_BIN=rea is the one spelling that
  // asks for exactly what this default would ask for.
  if (process.platform === 'win32' && bin === 'rea') {
    const entry = findWindowsReaEntry();
    if (entry) return { command: process.execPath, prefixArgs: [entry] };
  }
  return { command: bin, prefixArgs: [] };
}

function findWindowsReaEntry() {
  for (const raw of (process.env.PATH || '').split(';')) {
    // Windows PATH is REG_EXPAND_SZ and entries with spaces are commonly stored
    // quoted ("C:\Program Files\…"); the quotes are not part of the path. A
    // relative entry would resolve against our own cwd, which is not what the
    // operator's shell would do, so it is skipped rather than guessed at.
    const dir = raw.trim().replace(/^"(.*)"$/, '$1');
    if (!dir || !isAbsolute(dir)) continue;
    const entry = join(dir, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs');
    // No try/catch: existsSync is specified never to throw — it answers with a
    // boolean for every input, including malformed and over-long paths — so a
    // catch here would be unreachable code implying it is reachable.
    if (existsSync(entry)) return entry;
  }
  return null;
}

// Run `rea ... --format json` and return the parsed result envelope.
// rea streams progress as JSONL on long commands, so the whole-stdout parse
// is attempted first and the last parseable line second.
export function runReaJson(args, { timeoutMs = 60000 } = {}) {
  const bin = findReaBinary();
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let child;
    try {
      const { command, prefixArgs } = resolveSpawn(bin);
      child = spawn(command, [...prefixArgs, ...args, '--format', 'json'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        // No `timeout` option here on purpose. spawn's own timeout silently
        // killed the child at the deadline and let the close handler report a
        // timeout as "exited null without parseable JSON", so the accurate
        // message below was unreachable. One authority owns the deadline.
        // The VM egress needs the proxy for outbound traffic; rea itself does
        // not need it (it drives a local browser / reads local files), and the
        // browser path is handled separately by reaEnv.
        env: { ...process.env },
      });
    } catch (err) {
      return done({ ok: false, reason: `could not spawn rea binary (${bin}): ${err.message}` });
    }

    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      done({ ok: false, reason: `rea ${args[0]} timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    timer.unref?.();

    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', (err) => {
      clearTimeout(timer);
      done({ ok: false, reason: `rea binary not runnable (${bin}): ${err.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const parsed = parseReaOutput(stdout);
      if (parsed.error) {
        return done({ ok: false, reason: `rea ${args[0]} failed: ${parsed.error}` });
      }
      if (!parsed.ok) {
        const tail = stderr.trim().split('\n').pop() || stdout.trim().split('\n').pop() || '';
        return done({
          ok: false,
          reason: `rea ${args[0]} exited ${code} without parseable JSON${tail ? `: ${tail.slice(0, 160)}` : ''}`,
        });
      }
      done({ ok: true, envelope: parsed.envelope });
    });
  });
}

function parseReaOutput(stdout) {
  const text = stdout.trim();
  if (!text) return { ok: false };
  const tryParse = (line) => {
    try {
      const envelope = JSON.parse(line);
      if (!envelope || typeof envelope !== 'object') return null;
      if ('rea_progress' in envelope) return null; // progress line, not the result
      // REA error envelopes parse as JSON too — surface them as failures.
      if ('error' in envelope && !('normalized_result' in envelope)) {
        return { error: envelope.message || envelope.error || 'unknown REA error' };
      }
      return { ok: true, envelope };
    } catch {
      return null;
    }
  };
  const whole = tryParse(text);
  if (whole) return whole;
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line.startsWith('{')) continue;
    const parsed = tryParse(line);
    if (parsed) return parsed;
  }
  return { ok: false };
}

// --- browser capture -------------------------------------------------------
// Runs one bounded Playwright scenario against the target through the VM's
// browser prerequisites (reaEnv), and distils the evidence envelope into
// web-sized findings. The screenshot is returned as a data URL so the
// frontend can render it directly; it is capped — a huge page still fits the
// adapter's response budget.

export async function captureBrowser(url, { timeoutMs = 60000, settleMs = 4000 } = {}) {
  const { ensureBrowserCaptureEnv } = await import('./reaEnv.js');
  const env = await ensureBrowserCaptureEnv();
  if (!env.ok) return { ok: false, reason: env.reason };

  const scenario = {
    browser: { mode: 'connect', cdp_endpoint: env.cdpEndpoint, target_id: env.targetId },
    start_url: { url, query: [] },
    actions: [
      {
        step_id: 'load',
        action: 'goto',
        destination: { url, query: [] },
        wait_until: 'domcontentloaded',
      },
      { step_id: 'settle', action: 'wait_for_timeout', duration_ms: settleMs },
    ],
    capture: {
      after_each_step: ['screenshot'],
      at_end: ['url', 'screenshot'],
      events: ['console', 'network', 'page-errors'],
      network: { request_body: false, response_body: false, header_values: false },
    },
  };

  const dir = await mkdtemp(join(tmpdir(), 'reascan-scenario-'));
  const scenarioFile = join(dir, 'scenario.json');
  try {
    await writeFile(scenarioFile, JSON.stringify(scenario));
    const run = await runReaJson(['capture-browser-scenario', scenarioFile], { timeoutMs });
    if (!run.ok) return run;
    return { ok: true, capture: distilCapture(run.envelope) };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

function distilCapture(envelope) {
  const nr = envelope?.normalized_result ?? {};
  const steps = nr.steps ?? [];
  const events = nr.events?.items ?? [];

  const counts = { request: 0, response: 0, failed: 0, console: 0, pageError: 0 };
  const failedUrls = [];
  const pageErrors = [];
  const resourceTypes = {};
  for (const e of events) {
    if (e.kind === 'request') {
      counts.request++;
      const rt = e.resource_type || 'other';
      resourceTypes[rt] = (resourceTypes[rt] || 0) + 1;
    } else if (e.kind === 'response' || e.kind === 'request-finished') {
      counts.response++;
    } else if (e.kind === 'request-failed') {
      counts.failed++;
      const u = e.url;
      const us = typeof u === 'object' ? u?.url : u;
      if (us && failedUrls.length < 8) failedUrls.push({ url: String(us).slice(0, 120), failure: e.failure });
    } else if (e.kind === 'console') {
      counts.console++;
    } else if (e.kind === 'page-error') {
      counts.pageError++;
      if (pageErrors.length < 5) pageErrors.push(String(e.message ?? '').slice(0, 200));
    }
  }

  // Last screenshot across steps; capped so one giant page cannot blow the budget.
  let screenshot = null;
  for (let i = steps.length - 1; i >= 0; i--) {
    const shot = steps[i]?.artifacts?.screenshot?.value;
    if (shot?.data_base64 && shot.bytes < 500_000) {
      screenshot = `data:${shot.media_type || 'image/png'};base64,${shot.data_base64}`;
      break;
    }
  }

  const lastStep = steps[steps.length - 1];
  return {
    final_url: lastStep?.after_url?.url ?? null,
    duration_ms: nr.duration_ms ?? null,
    confidence: envelope?.confidence ?? null,
    screenshot,
    events: counts,
    resource_types: resourceTypes,
    failed_requests: failedUrls,
    page_errors: pageErrors,
    limitations: (nr.limitations ?? []).slice(0, 4).map(String),
  };
}

// --- deep JS analysis ------------------------------------------------------
// Downloads the page's script bundles into a temp dir (reusing the adapter's
// guarded fetch) and runs REA's static analyser over them. Caps are tighter
// than jsBundle's: this is the expensive path and it shares the request
// budget, so fewer, smaller bundles.

export async function analyzeJsDeep(url, safeFetch, { timeoutMs = 60000, maxBundles = 5, maxBytes = 2_000_000 } = {}) {
  const { extractScripts } = await import('../modules/jsBundle.js');

  // `timeoutMs` is this caller's budget for the WHOLE category, not just for the
  // REA subprocess. server.js hands us REQUEST_TIMEOUT_MS - 5000 and races the
  // result against its own deadline, so a call that spends its time downloading
  // bundles and then asks REA for a fresh full-length timeout can run past that
  // deadline — which rejects Promise.all and 504s the entire report, not just
  // jsDeep. Charging every phase against one deadline keeps the promise honest.
  const deadlineAt = Date.now() + timeoutMs;
  const remaining = () => Math.max(0, deadlineAt - Date.now());

  const dir = await mkdtemp(join(tmpdir(), 'reascan-jsdeep-'));
  try {
    const page = await safeFetch(url, { timeoutMs: Math.min(10000, remaining()) });
    if (!page.ok) return { ok: false, reason: `page fetch failed: ${page.reason}` };
    if (!page.response.ok) return { ok: false, reason: `page fetch returned HTTP ${page.response.status}` };

    const chunks = [];
    let size = 0;
    for await (const chunk of page.response.body) {
      size += chunk.length;
      if (size > 1_000_000) break;
      chunks.push(chunk);
    }
    const html = Buffer.concat(chunks).toString('utf8');
    const scripts = extractScripts(html, page.finalUrl).slice(0, maxBundles);
    if (scripts.length === 0) {
      return { ok: false, reason: 'no external <script src> found on the page' };
    }

    let downloaded = 0;
    for (const [i, src] of scripts.entries()) {
      // Stops on the clock; `downloaded` below reports how far it got.
      if (remaining() <= 0) break;
      try {
        const fetched = await safeFetch(src, { timeoutMs: Math.min(10000, remaining()) });
        if (!fetched.ok || !fetched.response.ok) continue;
        const bchunks = [];
        let bsize = 0;
        for await (const chunk of fetched.response.body) {
          bsize += chunk.length;
          if (bsize > maxBytes) break;
          bchunks.push(chunk);
        }
        await writeFile(join(dir, `bundle-${i}.js`), Buffer.concat(bchunks));
        downloaded++;
      } catch { /* one bad bundle must not kill the analysis */ }
    }
    if (downloaded === 0) {
      return { ok: false, reason: 'none of the page bundles could be downloaded' };
    }

    const budget = remaining();
    if (budget <= 0) {
      return { ok: false, reason: `downloading bundles used the whole ${timeoutMs}ms budget before REA could run` };
    }
    const run = await runReaJson(['analyze-javascript-application', dir], { timeoutMs: budget });
    if (!run.ok) return run;
    return { ok: true, analysis: distilJsAnalysis(run.envelope, downloaded) };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

// --- passive CDP page inspection --------------------------------------------
// One URL in, one distilled findings object out. Four `rea` CLI invocations are
// strung together, all charged against ONE deadline passed in by server.js
// ("timeoutMs" is the whole category's budget, not this phase's):
//
//   1. a fresh page target opened AT the url (reaEnv), then inspect-web-page
//   2. inspect-web-event-listeners (one selector: button)
//   3. discover-webmcp-tools
//   4. export-web-scripts, only when sources were retained
//
// The distilled payload carries counts, URLs, and digests — never script
// source text, DOM nodes, or storage values. Exported sources stay in a temp
// directory on the VM for local audit and are deleted in `finally`.

export async function inspectWebPage(url, safeFetch, { timeoutMs = 60000, observationMs = 900, exportScripts = true, browserEnv = null } = {}) {
  // Signature parity with analyzeJsDeep — callers always hand the guarded
  // fetch. This category never dials through it: the target is fetched by the
  // REA-managed browser itself, held inside the --allowed-origins policy every
  // CLI invocation below carries. The parameter stays so the dispatch contract
  // (callReaTool passes url + safeFetch to every category) does not fork.
  void safeFetch;

  let origin = null;
  try {
    origin = new URL(url).origin;
  } catch { /* falls through to the guard below */ }
  if (!origin || origin === 'null') {
    return { ok: false, reason: 'web.inspectPage requires an absolute http(s) URL' };
  }

  const deadlineAt = Date.now() + timeoutMs;
  const remaining = () => Math.max(0, deadlineAt - Date.now());

  // `browserEnv` is the test seam (same principle as the safeFetch DI the
  // modules carry): tests inject the env answer so the four CLI calls run
  // against a fake rea binary without a real browser anywhere near the box.
  // The boot answer deliberately carries NO mapped target: the browser boot is
  // memoised, so a caller that navigated the boot target ahead of us would
  // hand us a foreign page — live-verified as a blank inspection with a
  // confident verdict. This category therefore owns its target: newTargetAt
  // opens a page at the URL, every sub-call binds to it, and closeTarget runs
  // in the finally so repeat analyses do not leak pages into the profile.
  const { ensureBrowserCaptureEnv } = await import('./reaEnv.js');
  const boot = browserEnv
    ? await browserEnv()
    : await ensureBrowserCaptureEnv();
  if (!boot.ok) return { ok: false, reason: boot.reason };
  let newTargetAt = null;
  let closeTarget = null;
  if (!browserEnv) ({ newTargetAt, closeTarget } = await import('./reaEnv.js'));
  const fallbackClose = async () => ({ ok: true });
  const opener = newTargetAt ?? (async () => ({ cdpEndpoint: boot.cdpEndpoint, targetId: boot.targetId }));
  const closer = closeTarget ?? fallbackClose;

  const target = await opener(url);
  if (!target?.targetId) return { ok: false, reason: 'browser target could not be opened for inspection' };

  const limitations = [];
  const add = (l) => { const s = String(l); if (!limitations.includes(s)) limitations.push(s); };

  // Budget guard before the first REA window: a boot that ate the whole budget
  // must not hand REA a handful of milliseconds — that surfaces as "timed out
  // after 0ms" for a category that was never really tried.
  if (remaining() < 1000) {
    await closer(target.cdpEndpoint, target.targetId);
    return { ok: false, reason: `inspection skipped: only ${remaining()}ms of budget left after browser boot` };
  }

  try {
    const inspect = await runReaJson([
      'inspect-web-page', target.cdpEndpoint, target.targetId,
      '--allowed-origins', origin,
      '--observation-ms', String(observationMs),
      '--include-script-sources',
      '--include-storage-keys',
    ], { timeoutMs: remaining() });
    if (!inspect.ok) return inspect;

    const inspection = distilInspection(inspect.envelope, origin);

    // Sub-invocations are strictly optional evidence: one refusing must not
    // discard the category, it must be named in verdict.limitations instead.
    if (remaining() > 2000) {
      const listeners = await runReaJson([
        'inspect-web-event-listeners', target.cdpEndpoint, target.targetId,
        '--selector', 'button',
        '--allowed-origins', origin,
      ], { timeoutMs: remaining() });
      if (listeners.ok) {
        inspection.event_listeners = distilEventListeners(listeners.envelope, origin);
      } else {
        add(`inspect-web-event-listeners failed: ${listeners.reason}`);
      }
    } else {
      add('event listener probe skipped: not enough budget left');
    }

    if (remaining() > 2000) {
      const webmcp = await runReaJson([
        'discover-webmcp-tools', target.cdpEndpoint, target.targetId,
        '--allowed-origins', origin,
      ], { timeoutMs: remaining() });
      if (webmcp.ok) {
        inspection.webmcp_tools = distilWebmcpTools(webmcp.envelope);
      } else {
        add(`discover-webmcp-tools failed: ${webmcp.reason}`);
      }
    } else {
      add('WebMCP probe skipped: not enough budget left');
    }

    if (exportScripts && inspection.scripts_total > 0) {
      const budget = remaining();
      if (budget > 4000) {
        const dir = await mkdtemp(join(tmpdir(), 'reascan-webinspect-'));
        try {
          // The capture file holds the inspect envelope verbatim (re-serialised);
          // it contains the retained script sources, so it lives only in this
          // temp dir and the whole dir leaves in `finally`. The output directory
          // must not pre-exist — that is the CLI's contract.
          const captureFile = join(dir, 'page-inspection.json');
          await writeFile(captureFile, JSON.stringify(inspect.envelope));
          const exportRun = await runReaJson([
            'export-web-scripts', captureFile, join(dir, 'scripts'),
          ], { timeoutMs: remaining() });
          if (exportRun.ok) {
            const exported = distilExport(exportRun.envelope);
            inspection.exported_scripts = exported.total;
            mergeExportDigests(inspection.scripts, importedExportItems(exported.items));
          } else {
            add(`export-web-scripts failed: ${exportRun.reason}`);
          }
        } catch (err) {
          add(`export-web-scripts failed: ${err.message}`);
        } finally {
          await rm(dir, { recursive: true, force: true }).catch(() => {});
        }
      } else {
        inspection.exported_scripts = null;
        add(`script export skipped: not enough budget left (${budget}ms held)`);
      }
    } else if (inspection.scripts_total === 0) {
      add('no scripts were retained in the inspection window');
    }

    // REA's own result limitations travel to the verdict (via reaOutcome) — the
    // never-drop rule applies to the engine just as much as to a fetch.
    return { ok: true, inspection: { ...inspection, limitations: [...limitations, ...inspection.limitations] } };
  } finally {
    await closer(target.cdpEndpoint, target.targetId);
  }
}

const clip = (v, n = 200) => (v === null || v === undefined ? null : String(v).slice(0, n));

function hostOf(raw) {
  try {
    return new URL(String(raw)).hostname || null;
  } catch {
    return null;
  }
}

function countsByHost(urls) {
  const counts = {};
  for (const url of urls) {
    const host = hostOf(url);
    if (host) counts[host] = (counts[host] || 0) + 1;
  }
  return counts;
}

function distilInspection(envelope, origin) {
  const nr = envelope?.normalized_result ?? {};
  const target = nr.target ?? {};
  const items = Array.isArray(nr.scripts?.items) ? nr.scripts.items : [];

  // `source` (the script text REA retained) is the one field that must NEVER
  // cross this boundary — Count/URL/digest only. The pick below enumerates the
  // fields it copies rather than spreading the item, which is the guard: a new
  // verbose field in the envelope cannot leak into the payload by default.
  const scripts = items.slice(0, 10).map((item) => ({
    url: clip(item?.url ?? '(inline)'),
    is_module: item?.is_module === true,
    length: typeof item?.length === 'number' ? item.length : null,
    source_map_url: clip(item?.source_map_url),
    source_digest: item?.cdp_hash ? String(item.cdp_hash) : null,
  }));

  const resources = Array.isArray(nr.resources) ? nr.resources : [];
  const resourceTypes = {};
  for (const r of resources) {
    const t = String(r?.type ?? 'other');
    resourceTypes[t] = (resourceTypes[t] || 0) + 1;
  }

  const domUrls = (Array.isArray(nr.metadata?.dom_urls) ? nr.metadata.dom_urls : [])
    .filter((d) => typeof d?.url === 'string' && d.url)
    // A scope the engine never reported must not read as a green light: only
    // an explicit "approved" is treated as inside policy, everything else is
    // "outside" until the engine says otherwise.
    .map((d) => ({ url: d.url, scope: d.destination_scope === 'approved' ? 'approved' : 'outside' }));

  const thirdParty = new Set();
  for (const d of domUrls) {
    if (d.scope === 'outside') {
      const host = hostOf(d.url);
      if (host) thirdParty.add(host);
    }
  }
  const targetHost = hostOf(target.url ?? origin);
  for (const item of items) {
    const host = hostOf(item?.origin ?? item?.url);
    if (host && host !== targetHost) thirdParty.add(host);
  }

  const storage = nr.storage ?? {};
  const keyArrays = [
    storage.local_storage_keys,
    storage.session_storage_keys,
    storage.indexed_db_names,
    storage.cache_names,
  ];
  return {
    scripts_total: nr.scripts?.total ?? items.length,
    scripts,
    script_domain_counts: countsByHost(items.map((i) => i?.origin ?? i?.url)),
    resource_type_counts: resourceTypes,
    third_party: {
      approved_dom_urls: domUrls.filter((d) => d.scope === 'approved').map((d) => clip(d.url)).slice(0, 12),
      outside_policy_dom_urls: domUrls.filter((d) => d.scope === 'outside').map((d) => clip(d.url)).slice(0, 12),
      third_party_domains: (Array.from(thirdParty)).slice(0, 12),
    },
    event_listeners: [],
    webmcp_tools: [],
    storage: {
      origin: clip(storage.origin),
      usage_bytes: typeof storage.usage_bytes === 'number' ? storage.usage_bytes : null,
      quota_bytes: typeof storage.quota_bytes === 'number' ? storage.quota_bytes : null,
      // Values and names never ship; presence is the evidence. The key names
      // REA carried in the capture stay in the temp file and nowhere else.
      has_keys: keyArrays.some((a) => Array.isArray(a) && a.length > 0),
    },
    workers: Number.isInteger(nr.workers?.length) ? nr.workers.length : 0,
    console_events: Number.isInteger(nr.console?.events?.length) ? nr.console.events.length : 0,
    network_requests: Number.isInteger(nr.network?.requests?.length) ? nr.network.requests.length : 0,
    target: {
      title: clip(target.title),
      url: clip(target.url),
      origin: clip(target.origin ?? origin),
    },
    confidence: envelope?.confidence ?? null,
    // Key engine caveats, first sentence only — these speak for five longer
    // variants of the same caveat.
    limitations: (nr.limitations ?? []).slice(0, 4).map((l) => String(l).split('. ')[0]).slice(0, 4),
  };
}

function distilEventListeners(envelope, origin) {
  const nr = envelope?.normalized_result ?? {};
  return (Array.isArray(nr.listeners) ? nr.listeners : [])
    .slice(0, 5)
    .map((l) => ({
      type: clip(l?.type, 40),
      // The callback's script URL can sit outside the allowed origin (a
      // framework bundle on a CDN) — that URL is evidence, kept verbatim.
      url: clip(l?.location?.url),
      line: Number.isInteger(l?.location?.line_number) ? l.location.line_number : null,
      column: Number.isInteger(l?.location?.column_number) ? l.location.column_number : null,
    }));
}

function distilWebmcpTools(envelope) {
  const nr = envelope?.normalized_result ?? {};
  const items = Array.isArray(nr.tools?.items) ? nr.tools.items : [];
  const names = new Set();
  for (const item of items) {
    const name = item?.name ?? item?.tool ?? null;
    if (name) names.add(clip(name, 120));
    if (names.size >= 12) break;
  }
  // Page-declared metadata is untrusted: only the name travels. The tag keeps
  // the reader from firing at the page based on a self-declared surface.
  return Array.from(names).map((name) => ({ name, declared: true }));
}

function distilExport(envelope) {
  const nr = envelope?.normalized_result ?? {};
  const scripts = Array.isArray(nr.scripts) ? nr.scripts : [];
  return {
    total: scripts.length,
    items: scripts.map((s) => ({
      url: clip(s?.url),
      sha256: typeof s?.content?.sha256 === 'string' ? s.content.sha256 : null,
      bytes: typeof s?.content?.bytes === 'number' ? s.content.bytes : null,
    })),
  };
}

// Kept separate from distilExport for tests: the merge only ever replaces a
// digest, never adds a new script — a mismatch is a REA shell quirk that must
// not grow the payload.
function importedExportItems(items) {
  return items.filter((i) => i.sha256);
}

function mergeExportDigests(scripts, exported) {
  const byUrl = new Map(exported.map((e) => [e.url, e.sha256]));
  const byPath = new Map(exported.map((e) => [hostPathOf(e.url), e.sha256]));
  for (const script of scripts) {
    const digest = byUrl.get(script.url) ?? byPath.get(hostPathOf(script.url));
    if (digest) script.source_digest = digest;
  }
}

// Export URLs keep their query/fragment identity, while inspect inventory URLs
// sometimes differ only by those — matching on scheme+host+path is the honest
// common denominator.
function hostPathOf(raw) {
  try {
    const u = new URL(String(raw));
    return `${u.host}${u.pathname}`;
  } catch {
    return null;
  }
}
function distilJsAnalysis(envelope, filesDownloaded) {
  const nr = envelope?.normalized_result ?? {};
  const stats = nr.statistics ?? {};
  const sg = nr.semantic_graph ?? {};
  const unknowns = (sg.unknowns ?? []).slice(0, 6).map((u) => {
    if (typeof u === 'string') return u;
    if (u && typeof u === 'object') {
      return u.message || u.description || u.label || JSON.stringify(u).slice(0, 160);
    }
    return String(u);
  });
  return {
    files_analysed: filesDownloaded,
    modules: stats.modules ?? null,
    findings: stats.findings ?? null,
    ast_nodes_visited: stats.visited_ast_nodes ?? null,
    parse_failures: stats.parse_failures ?? null,
    coverage_status: sg.coverage?.status ?? null,
    unknowns,
    confidence: envelope?.confidence ?? null,
    limitations: (nr.limitations ?? []).slice(0, 4).map(String),
  };
}
