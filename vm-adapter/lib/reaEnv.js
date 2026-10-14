// Browser-capture prerequisites for REA on this VM.
//
// REA's `capture-browser-scenario` can attach to an already-running Chromium
// over CDP ("connect" mode), but it strips proxy env vars from any browser it
// launches itself — and this VM reaches the internet only through an
// authenticated egress proxy. So the adapter ensures two local helpers:
//
//   1. A CONNECT forwarder on 127.0.0.1:18080 that injects Proxy-Authorization
//      for the upstream egress proxy (script at REA_PROXY_SCRIPT).
//   2. A headless Chromium on 127.0.0.1:9222 (CDP) launched with
//      --proxy-server pointing at the forwarder.
//
// Both are started on demand and left running; concurrent analyses share them.
// Every function answers {ok:true,...} | {ok:false, reason} — never throws.

import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PROXY_PORT = Number(process.env.REA_PROXY_PORT) || 18080;
const CDP_PORT = Number(process.env.REA_CDP_PORT) || 9222;
const PROXY_SCRIPT = process.env.REA_PROXY_SCRIPT
  || joinHome('workspace/rea-proxy/proxy.mjs');
const CHROME_BIN = process.env.REA_CHROME_BIN || '/opt/meta-chromium/chrome';

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

// Parse https_proxy (http://user:pass@host:port) into upstream parts for the
// forwarder, which needs them as separate env vars.
function parseUpstreamProxy() {
  const raw = process.env.https_proxy || process.env.HTTPS_PROXY || '';
  const m = raw.match(/^https?:\/\/([^:]+):([^@]+)@([^:]+):(\d+)/);
  if (!m) return null;
  return { user: m[1], pass: m[2], host: m[3], port: m[4] };
}

async function ensureProxyForwarder() {
  if (await tcpConnectable(PROXY_PORT)) return { ok: true };
  const upstream = parseUpstreamProxy();
  if (!upstream) {
    return { ok: false, reason: 'proxy forwarder not running and no https_proxy to derive upstream auth from' };
  }
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
    child.unref();
  } catch (err) {
    return { ok: false, reason: `could not start proxy forwarder: ${err.message}` };
  }
  for (let i = 0; i < 10; i++) {
    await sleep(500);
    if (await tcpConnectable(PROXY_PORT)) return { ok: true };
  }
  return { ok: false, reason: `proxy forwarder did not come up on 127.0.0.1:${PROXY_PORT}` };
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

async function ensureChromeCdp() {
  // Already up? Open a fresh page target on it.
  try {
    await httpGetJson(`http://127.0.0.1:${CDP_PORT}/json/version`);
    const fresh = await newPageTarget().catch(() => null);
    if (fresh) return { ok: true, ...fresh };
  } catch { /* not up — launch it */ }

  // The browser must not inherit the raw egress proxy vars: Chromium would try
  // (and fail) to use the authenticated proxy itself. It only gets the local
  // forwarder, which needs no auth.
  const env = { ...process.env };
  delete env.http_proxy; delete env.https_proxy;
  delete env.HTTP_PROXY; delete env.HTTPS_PROXY;

  try {
    const child = spawn(CHROME_BIN, [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      // The VM's egress proxy terminates TLS with its own CA ("Hatch Sandbox
      // Egress CA"), which Chromium does not trust. This is a controlled
      // analysis environment, not interactive browsing: analysis targets are
      // validated by the adapter's SSRF guard before the browser ever sees
      // them, so ignoring the proxy's MITM certificate is the correct trade.
      '--ignore-certificate-errors',
      `--proxy-server=http://127.0.0.1:${PROXY_PORT}`,
      // Local addresses must bypass the proxy: the forwarder only speaks to
      // the upstream egress proxy, which cannot route back to this VM's
      // loopback (and must never be asked to).
      '--proxy-bypass-list=127.0.0.1,localhost,::1',
      `--remote-debugging-port=${CDP_PORT}`,
      '--user-data-dir=/tmp/reascan-chrome-profile',
      'about:blank',
    ], { detached: true, stdio: 'ignore', env });
    child.unref();
  } catch (err) {
    return { ok: false, reason: `could not launch Chromium (${CHROME_BIN}): ${err.message}` };
  }
  for (let i = 0; i < 20; i++) {
    await sleep(500);
    try {
      await httpGetJson(`http://127.0.0.1:${CDP_PORT}/json/version`);
      const fresh = await newPageTarget().catch(() => null);
      if (fresh) return { ok: true, ...fresh };
    } catch { /* still starting */ }
  }
  return { ok: false, reason: `Chromium CDP did not come up on 127.0.0.1:${CDP_PORT}` };
}

// Ensure the full browser-capture environment. Idempotent: running helpers
// are reused, missing ones are started.
export async function ensureBrowserCaptureEnv() {
  const proxy = await ensureProxyForwarder();
  if (!proxy.ok) return proxy;
  return ensureChromeCdp();
}
