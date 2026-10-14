// Analysis engine HTTP surface. Reached only through the Cloudflare Tunnel, never
// directly — the tunnel dials out, so the VM keeps no inbound port.
//
// Every response is JSON shaped {status, ...} with status in 'done' | 'error'.
// Nothing here throws across the boundary; a hostile target must not be able to
// turn an analysis into a dead socket.

import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { safeFetch, validateUrl } from './lib/urlGuard.js';
import { fingerprint } from './modules/fingerprint.js';
import { analyzeBundles } from './modules/jsBundle.js';
import { callReaTool, REA_TOOLS } from './lib/reaMcp.js';

// The Pages Function allows this request 60s end to end, so the two analyses share
// one budget rather than each getting a full slice of it.
const REQUEST_TIMEOUT_MS = 70000;
const MAX_BODY_BYTES = 8192;

// Comparing lengths first is not optional: timingSafeEqual throws on buffers of
// different lengths, and branching on length alone would be a shorter oracle than
// the constant-time compare it sits in front of.
function keyMatches(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Aggregate confidence across every finding. A single weak reading caps the
// verdict rather than being averaged away by strong ones.
function buildVerdict(findings, limitations) {
  const rank = { high: 3, medium: 2, low: 1 };
  let confidence = 'high';
  for (const f of findings) {
    if (!rank[f.confidence]) continue;
    if (rank[f.confidence] < rank[confidence]) confidence = f.confidence;
  }

  const unknowns = [];
  if (findings.some((f) => f.key === 'cdn')) {
    unknowns.push('When a CDN fronts the target, the origin server is not observable from here — the header describes the edge, not the backend.');
  }
  if (findings.some((f) => f.key === 'framework')) {
    unknowns.push('A framework marker in markup suggests what is served, not what is deployed. The served bundle can differ from the build on disk.');
  }

  // No findings at all is a low-confidence result, not a high-confidence "clean".
  if (findings.length === 0) confidence = 'low';

  return { confidence, limitations, unknowns };
}

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

// Turn a successful {ok:true, capture|analysis} REA answer into the task shape
// the rest of handleAnalyze consumes. Exported so node --test can pin the
// hoisting without spawning a browser or the rea binary.
//
// distilCapture/distilJsAnalysis carry their own limitations (a failed
// screenshot step, a bundle the engine could not parse). Hoisting them into the
// task result is what lands them in verdict.limitations — silently discarding
// them would break the "never drop a limitation" rule in AGENTS.md. The field
// is then stripped from the payload, the same shape fingerprint and js_bundles
// already ship: findings only in the section, limitations only in the verdict.
export function reaOutcome(result) {
  const { limitations = [], ...data } = result.capture ?? result.analysis ?? {};
  return { data: Object.keys(data).length ? data : null, limitations: limitations.map(String) };
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return { ok: false, reason: 'request body too large' };
    chunks.push(chunk);
  }
  return { ok: true, text: Buffer.concat(chunks).toString('utf8') };
}

async function handleAnalyze(req, res, env) {
  const body = await readBody(req);
  if (!body.ok) return send(res, 422, { status: 'error', error: body.reason });

  let payload;
  try {
    payload = JSON.parse(body.text);
  } catch {
    return send(res, 422, { status: 'error', error: 'body is not valid JSON' });
  }

  const check = await validateUrl(payload?.url);
  if (!check.ok) return send(res, 422, { status: 'error', error: check.reason });

  const started = Date.now();
  const requested = Array.isArray(payload.categories) && payload.categories.length
    ? payload.categories
    : ['fingerprint', 'jsBundle'];

  // Both modules take url first and a guard second; categories decide which run,
  // not how they are called. A throw from either degrades to an empty result so
  // one broken category cannot cost the caller the whole report.
  // The REA categories follow the same contract: callReaTool never throws, and
  // an {ok:false} answer becomes a limitation, not a failed request.
  const emptyFp = { findings: [], cdn: null, tls: null, limitations: [] };
  const emptyBundles = { bundles: [], limitations: [] };
  const emptyRea = { data: null, limitations: [] };

  const fpTask = requested.includes('fingerprint')
    ? fingerprint(check.url.toString(), safeFetch)
      .catch((e) => ({ ...emptyFp, limitations: [`fingerprint aborted: ${e.message}`] }))
    : Promise.resolve(emptyFp);

  const bundleTask = requested.includes('jsBundle')
    ? analyzeBundles(check.url.toString(), safeFetch)
    : Promise.resolve(emptyBundles);

  const reaTask = async (tool) => {
    try {
      const result = await callReaTool(tool, {
        url: check.url.toString(),
        safeFetch,
        timeoutMs: REQUEST_TIMEOUT_MS - 5000,
      });
      if (result.ok) return reaOutcome(result);
      return { ...emptyRea, limitations: [`${tool}: ${result.reason}`] };
    } catch (e) {
      return { ...emptyRea, limitations: [`${tool} aborted: ${e.message}`] };
    }
  };

  const browserTask = requested.includes('browserCapture')
    ? reaTask('browser.capture')
    : Promise.resolve(emptyRea);

  const jsDeepTask = requested.includes('jsDeep')
    ? reaTask('js.analyzeDeep')
    : Promise.resolve(emptyRea);

  // Worst case for jsBundle is 40 bundles across 6 workers at 10s each, which is
  // roughly 70s — right at the edge of the 75s the Pages Function allows this
  // whole request. The
  // per-fetch timeouts inside the modules are not enough on their own, so the
  // overall budget is enforced here and the caller gets a 504 instead of hanging.
  // Work already in flight is abandoned rather than cancelled: the modules take
  // no external signal, and it stays bounded by their own fetch timeouts.
  const deadline = new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error(`analysis exceeded ${REQUEST_TIMEOUT_MS}ms`)), REQUEST_TIMEOUT_MS);
    timer.unref?.();
  });

  let fp;
  let bundles;
  let browser;
  let jsDeep;
  try {
    [fp, bundles, browser, jsDeep] = await Promise.race([
      Promise.all([fpTask, bundleTask, browserTask, jsDeepTask]),
      deadline,
    ]);
  } catch (err) {
    return send(res, 504, { status: 'error', error: err.message });
  }

  const limitations = [...fp.limitations, ...bundles.limitations, ...browser.limitations, ...jsDeep.limitations];
  const verdict = buildVerdict(fp.findings, limitations);

  return send(res, 200, {
    status: 'ok',
    findings: {
      url: payload.url,
      timestamp: new Date().toISOString(),
      fingerprint: { findings: fp.findings, cdn: fp.cdn, tls: fp.tls },
      js_bundles: bundles.bundles,
      browser_capture: browser.data,
      js_deep: jsDeep.data,
      verdict,
    },
    duration_ms: Date.now() - started,
  });
}

export function createAdapter(env) {
  return createServer(async (req, res) => {
    try {
      // No request without a key, including health checks. If API_KEY is unset
      // the server must not start rather than serve unauthenticated.
      if (!env.API_KEY) {
        return send(res, 500, { status: 'error', error: 'API_KEY is not configured on the adapter' });
      }
      if (!keyMatches(req.headers['x-api-key'], env.API_KEY)) {
        return send(res, 401, { status: 'error', error: 'unauthorised' });
      }

      if (req.method === 'GET' && req.url === '/health') {
        return send(res, 200, { status: 'ok', tools_available: ['fingerprint', 'jsBundle', 'browserCapture', 'jsDeep'], rea_tools: REA_TOOLS });
      }
      if (req.method === 'POST' && req.url === '/analyze') {
        return await handleAnalyze(req, res, env);
      }

      return send(res, 404, { status: 'error', error: 'not found' });
    } catch (err) {
      // An unexpected throw is still an answer, not a dropped connection.
      if (!res.headersSent) {
        return send(res, 500, { status: 'error', error: `internal error: ${err.message}` });
      }
      res.end();
    }
  });
}

// Started only when this file is the entry point, so tests can import createAdapter
// without a server coming up behind them. pathToFileURL rather than string
// concatenation because import.meta.url is percent-encoded and slash-normalised
// — building `file://${argv[1]}` by hand works on Linux and silently fails on
// Windows, where the drive letter and backslashes do not match.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT) || 8787;
  // Loopback by default, deliberately. The architecture assumes the adapter has no
  // inbound port at all — Cloudflare Tunnel dials out to it. listen(port) with no
  // host binds "::", which would expose the adapter on every interface and leave
  // the API key as the only thing between the internet and the analysis engine.
  const host = process.env.HOST || '127.0.0.1';
  const server = createAdapter(process.env);
  server.listen(port, host, () => {
    process.stderr.write(`reascan adapter listening on ${host}:${port}\n`);
  });
}