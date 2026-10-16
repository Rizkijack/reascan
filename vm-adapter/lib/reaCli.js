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
    try {
      if (existsSync(entry)) return entry;
    } catch { /* unreadable PATH entry */ }
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

  const dir = await mkdtemp(join(tmpdir(), 'reascan-jsdeep-'));
  try {
    const page = await safeFetch(url, { timeoutMs: 10000 });
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
      try {
        const fetched = await safeFetch(src, { timeoutMs: 10000 });
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

    const run = await runReaJson(['analyze-javascript-application', dir], { timeoutMs });
    if (!run.ok) return run;
    return { ok: true, analysis: distilJsAnalysis(run.envelope, downloaded) };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
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
