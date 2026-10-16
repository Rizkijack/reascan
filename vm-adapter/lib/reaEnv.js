// Browser-capture prerequisites for REA on this VM.
//
// REA's `capture-browser-scenario` can attach to an already-running Chromium
// over CDP ("connect" mode), but it strips proxy env vars from any browser it
// launches itself — and a host behind an authenticated egress proxy therefore
// needs a shim. So the adapter ensures two local helpers:
//
//   1. A CONNECT forwarder on 127.0.0.1:18080 that injects Proxy-Authorization
//      for the upstream egress proxy (script at REA_PROXY_SCRIPT). Started only
//      when https_proxy actually names an upstream; a host with direct egress
//      runs no forwarder and gets no proxy flags.
//   2. A headless Chromium on 127.0.0.1:9222 (CDP) launched with
//      --proxy-server pointing at the forwarder.
//
// Both are started on demand and left running; concurrent analyses share them.
// Every function answers {ok:true,...} | {ok:false, reason} — never throws.

import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const PROXY_PORT = Number(process.env.REA_PROXY_PORT) || 18080;
const CDP_PORT = Number(process.env.REA_CDP_PORT) || 9222;
const PROXY_SCRIPT = process.env.REA_PROXY_SCRIPT
  || joinHome('workspace/rea-proxy/proxy.mjs');
const CHROME_BIN = process.env.REA_CHROME_BIN || '/opt/meta-chromium/chrome';
// One profile dir per host, reused across runs: Chrome refuses a second launch
// against a profile already in use, and concurrent analyses share this instance.
// Derived from tmpdir() rather than a fixed /tmp path, which Windows would
// resolve to a drive root it may not be allowed to write.
const CHROME_PROFILE = process.env.REA_CHROME_PROFILE || join(tmpdir(), 'reascan-chrome-profile');

function joinHome(...parts) {
  const home = process.env.HOME || '/home/hatch';
  return [home, ...parts].join('/');
}

async function tcpConnectable(port, host = '127.0.0.1', timeoutMs = 1500) {
  const { default: net } = await import('node:net');
  return new Promise((resolve) => {
    const sock = net.connect(port, host);
    const done = (ok) => { try { sock.destroy(); } catch {} resolve(ok); };
    const timer = setTimeout(() => done(false), timeoutMs);
    timer.unref?.();
    sock.on('connect', () => { clearTimeout(timer); done(true); });
    sock.on('error', () => { clearTimeout(timer); done(false); });
  });
}

async function httpGetJson(url, timeoutMs = 5000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Read the configured egress proxy. Three states, deliberately kept apart —
// collapsing them would turn a misconfigured proxy into a silently direct-egress
// capture, which then reports a screenshot of an error page as if it were
// evidence:
//   null       no proxy configured at all; direct egress is genuinely available
//   {opaque}   a proxy IS configured but exposes no user:pass@host:port the
//              forwarder could inject, so this host cannot reach the internet
//   {user,...} proxy configured with credentials the forwarder can inject
export function parseUpstreamProxy() {
  const raw = process.env.https_proxy || process.env.HTTPS_PROXY
    || process.env.http_proxy || process.env.HTTP_PROXY || '';
  if (!raw.trim()) return null;
  const m = /^https?:\/\/([^:]+):([^@]+)@([^:]+):(\d+)/i.exec(raw.trim());
  if (!m) return { opaque: true };
  return { user: m[1], pass: m[2], host: m[3], port: m[4] };
}

// Browser flags that depend on how egress is reached.
//
// `--ignore-certificate-errors` is a TLS bypass. Behind the VM's MITM egress
// proxy it is required — the proxy terminates TLS with its own CA ("Hatch
// Sandbox Egress CA") that Chromium does not trust. On direct egress there is
// nothing to bypass and applying it would carry that weakness onto a host whose
// certificates are valid, so it is opt-in there via REA_IGNORE_CERT_ERRORS.
// Analysis targets are validated by the adapter's SSRF guard before the browser
// ever sees them; that guard is why a bad certificate can be tolerated at all.
export function proxyArgsFor(mode) {
  const args = [];
  if (mode === 'forwarder' || process.env.REA_IGNORE_CERT_ERRORS === '1') {
    args.push('--ignore-certificate-errors');
  }
  if (mode === 'forwarder') {
    args.push(
      `--proxy-server=http://127.0.0.1:${PROXY_PORT}`,
      // Local addresses must bypass the proxy: the forwarder only speaks to
      // the upstream egress proxy, which cannot route back to this VM's
      // loopback (and must never be asked to).
      '--proxy-bypass-list=127.0.0.1,localhost,::1',
    );
  }
  return args;
}

// Returns {ok:true, mode:'forwarder'} when traffic must pass through the local
// CONNECT forwarder, {ok:true, mode:'direct'} when no proxy is configured at
// all, and {ok:false, reason} whenever a proxy IS configured but this host
// cannot get through it — that is a genuine loss of egress, and reporting it as
// a clean direct capture would be evidence fraud.
async function ensureProxyForwarder() {
  if (await tcpConnectable(PROXY_PORT)) return { ok: true, mode: 'forwarder' };
  const upstream = parseUpstreamProxy();
  if (!upstream) return { ok: true, mode: 'direct' };
  if (upstream.opaque) {
    return {
      ok: false,
      reason: 'an egress proxy is configured but exposes no user:pass@host:port for the forwarder to inject — this host cannot reach the internet through it',
    };
  }
  // A failed spawn is an asynchronous 'error' event, and an EventEmitter with
  // no 'error' listener throws it as an uncaughtException — which would take
  // the whole adapter down. The readiness poll decides the outcome; this only
  // records why, so the failure names the cause instead of arriving blank.
  let spawnError = null;
  try {
    const child = spawn(process.execPath, [PROXY_SCRIPT], {
      detached: true,
      stdio: 'ignore',
      env: {
        ...process.env,
        UPSTREAM_PROXY_USER: upstream.user,
        UPSTREAM_PROXY_PASS: upstream.pass,
        UPSTREAM_PROXY_HOST: upstream.host,
        UPSTREAM_PROXY_PORT: upstream.port,
        LISTEN_PORT: String(PROXY_PORT),
      },
    });
    child.on('error', (err) => { spawnError = err; });
    child.unref();
  } catch (err) {
    return { ok: false, reason: `could not start proxy forwarder: ${err.message}` };
  }
  for (let i = 0; i < 10; i++) {
    if (spawnError) break;
    await sleep(500);
    if (await tcpConnectable(PROXY_PORT)) return { ok: true, mode: 'forwarder' };
  }
  return {
    ok: false,
    reason: `proxy forwarder did not come up on 127.0.0.1:${PROXY_PORT}`
      + (spawnError ? ` — could not start ${PROXY_SCRIPT}: ${spawnError.message}` : ''),
  };
}

async function httpPutJson(url, timeoutMs = 5000) {
  const res = await fetch(url, { method: 'PUT', signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Open a fresh blank page target for this capture. Reusing an arbitrary
// existing target is racy: the target can close between discovery and the
// REA call, which surfaces as target_unavailable. A fresh target is ours.
async function newPageTarget() {
  const target = await httpPutJson(`http://127.0.0.1:${CDP_PORT}/json/new?about:blank`);
  if (!target?.id) throw new Error('CDP did not return a new target id');
  return { cdpEndpoint: `http://127.0.0.1:${CDP_PORT}`, targetId: target.id };
}

async function ensureChromeCdp(mode) {
  // Already up? Open a fresh page target on it.
  let cdpAnswered = false;
  try {
    await httpGetJson(`http://127.0.0.1:${CDP_PORT}/json/version`);
    cdpAnswered = true;
  } catch { /* not up — launch it */ }

  if (cdpAnswered) {
    const fresh = await newPageTarget().catch(() => null);
    if (fresh) return { ok: true, ...fresh };
    // A live CDP browser that will not hand out a target is its own failure.
    // Falling through to the port-collision branch here would be a provably
    // false diagnosis — we just spoke the DevTools HTTP API to that process.
    return { ok: false, reason: `a CDP browser is up on 127.0.0.1:${CDP_PORT} but refused to open a new page target` };
  }

  // Nothing answers CDP, yet the port is taken. Launching anyway dies on a bind
  // conflict and reports only "did not come up"; Chrome is not the only thing
  // that binds a debugging port on a developer machine.
  if (await tcpConnectable(CDP_PORT)) {
    return {
      ok: false,
      reason: `127.0.0.1:${CDP_PORT} is held by a process that does not answer the DevTools HTTP API — free it or set REA_CDP_PORT`,
    };
  }

  // The browser must not inherit the raw egress proxy vars: Chromium would try
  // (and fail) to use the authenticated proxy itself. It only gets the local
  // forwarder, which needs no auth.
  const env = { ...process.env };
  delete env.http_proxy; delete env.https_proxy;
  delete env.HTTP_PROXY; delete env.HTTPS_PROXY;

  // Both failure shapes are recorded rather than thrown. A missing binary is an
  // asynchronous 'error' event, and an EventEmitter without an 'error' listener
  // rethrows it as an uncaughtException that kills the adapter — so a host with
  // no Chromium would lose the process instead of losing one category.
  let chromeExit = null;
  let spawnError = null;
  try {
    const child = spawn(CHROME_BIN, [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      ...proxyArgsFor(mode),
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${CHROME_PROFILE}`,
      'about:blank',
    ], { detached: true, stdio: 'ignore', env });
    child.on('error', (err) => { spawnError = err; });
    child.on('exit', (code) => { chromeExit = code; });
    child.unref();
  } catch (err) {
    return { ok: false, reason: `could not launch Chromium (${CHROME_BIN}): ${err.message}` };
  }
  for (let i = 0; i < 20; i++) {
    if (spawnError) break;
    await sleep(500);
    try {
      await httpGetJson(`http://127.0.0.1:${CDP_PORT}/json/version`);
      const fresh = await newPageTarget().catch(() => null);
      if (fresh) return { ok: true, ...fresh };
    } catch { /* still starting */ }
  }
  return {
    ok: false,
    reason: `Chromium CDP did not come up on 127.0.0.1:${CDP_PORT}`
      + (spawnError
        ? ` — Chromium could not be started (${CHROME_BIN}): ${spawnError.message}`
        : chromeExit !== null
          ? ` — Chromium exited with code ${chromeExit}; a profile directory still held by an orphaned Chrome is a known cause, so try a different REA_CHROME_PROFILE`
          : ''),
  };
}

// Cold start is a multi-second operation that launches processes against one
// shared profile directory and one shared port. Concurrent analyses must share a
// single attempt: racing it means N browsers against the same profile lock, and
// every loser fails. Cleared once settled so the next call re-checks the live
// state rather than replaying a stale answer.
let envInFlight = null;

// Ensure the full browser-capture environment. Idempotent: running helpers
// are reused, missing ones are started.
export async function ensureBrowserCaptureEnv() {
  if (!envInFlight) {
    envInFlight = (async () => {
      try {
        const proxy = await ensureProxyForwarder();
        if (!proxy.ok) return proxy;
        return await ensureChromeCdp(proxy.mode);
      } finally {
        envInFlight = null;
      }
    })();
  }
  return envInFlight;
}
