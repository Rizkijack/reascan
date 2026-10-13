// JS bundle inventory — what the page loads, how big it is, whether it ships a
// sourcemap, which endpoint-shaped literals appear in it, and whether the code
// looks obfuscated.
//
// Two rules from AGENTS.md shape this file:
//   - nothing is dropped silently. A bundle that fails, times out or exceeds a
//     limit becomes a limitation, never a missing row.
//   - no secret-pattern detection. An endpoint is reported because the literal is
//     in the file, not because its name looks sensitive.
//
// safeFetch is injected. This module cannot open a socket on its own.

import { readCapped } from '../lib/body.js';

export const DEFAULT_LIMITS = { maxBundles: 40, maxBytes: 1048576, timeoutMs: 10000 };

// A page can reference hundreds of scripts; only API-shaped literals are worth
// reporting and a minified bundle holds thousands of strings.
const MAX_ENDPOINTS_PER_BUNDLE = 25;

// Signatures that indicate deliberate obfuscation. Entropy scoring is not
// implemented — these are markers, so the finding stays a derivation.
const OBFUSCATION_SIGNATURES = [
  'eval(atob(',
  'eval(function(p,a,c,k,e,',
  'eval(function(p,a,c,k,e,d,',
  '_0x',
  '_0x1',
];

function extractScriptSrc(html) {
  const sources = [];
  const pattern = /<script\b[^>]*\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let match;
  while ((match = pattern.exec(html)) !== null) {
    const raw = (match[2] ?? match[3] ?? match[4] ?? '').trim();
    if (raw) sources.push(raw);
  }
  return sources;
}

// Absolute + deduped. Relative sources resolve against the page we actually
// landed on, not the URL the user typed — a redirect changes what resolves.
function resolveSources(sources, baseUrl, limitations) {
  const resolved = [];
  for (const src of sources) {
    if (src.startsWith('data:') || src.startsWith('blob:')) continue;
    let absolute;
    try {
      absolute = new URL(src, baseUrl).toString();
    } catch {
      limitations.push(`could not resolve script src: ${src}`);
      continue;
    }
    if (!resolved.includes(absolute)) resolved.push(absolute);
  }
  return resolved;
}

// Endpoints are observations of a literal in the file. That a literal *is* an API
// route is a step further, which is why the finding only claims the literal.
function extractEndpoints(source) {
  const pattern = /["'`](\/[A-Za-z0-9_\-./:{}$]{2,120})["'`]/g;
  const seen = [];
  let match;
  while ((match = pattern.exec(source)) !== null) {
    const path = match[1];
    if (!/^\/(api|v\d+|graphql|rest|rpc|oauth|auth|ws)\b/i.test(path)) continue;
    if (path.endsWith('.js') || path.endsWith('.css') || path.endsWith('.map')) continue;
    if (!seen.includes(path)) seen.push(path);
    if (seen.length >= MAX_ENDPOINTS_PER_BUNDLE) break;
  }
  return seen;
}

function detectObfuscation(source) {
  return OBFUSCATION_SIGNATURES.find((sig) => source.includes(sig)) ?? null;
}

async function analyseBundle(src, safeFetch, limits, limitations) {
  const fetched = await safeFetch(src, { timeoutMs: limits.timeoutMs });
  if (!fetched.ok) {
    limitations.push(`${src}: ${fetched.reason}`);
    return null;
  }

  const body = await readCapped(fetched.response, limits.maxBytes);
  if (body.truncated) {
    limitations.push(`${src}: exceeds ${limits.maxBytes} byte limit, analysed the first ${limits.maxBytes} bytes`);
  }

  const sourcemap = /\/\/[#@]\s*sourceMappingURL=/.test(body.text);
  const endpoints = extractEndpoints(body.text);
  const signature = detectObfuscation(body.text);

  const bundle = {
    src,
    size_kb: Math.round(body.bytes / 1024),
    sourcemap,
    endpoints,
    obfuscated: signature !== null,
  };

  if (signature) bundle.obfuscation_marker = signature;
  if (endpoints.length === MAX_ENDPOINTS_PER_BUNDLE) {
    limitations.push(`${src}: endpoint list capped at ${MAX_ENDPOINTS_PER_BUNDLE}, more may be present`);
  }

  return bundle;
}

export async function analyzeBundles(url, safeFetch, limits = {}) {
  const merged = { ...DEFAULT_LIMITS, ...limits };
  const bundles = [];
  const limitations = [];

  const page = await safeFetch(url, { timeoutMs: merged.timeoutMs });
  if (!page.ok) {
    limitations.push(`page fetch failed: ${page.reason}`);
    return { bundles, limitations };
  }

  const pageBody = await readCapped(page.response, merged.maxBytes);
  if (pageBody.truncated) {
    limitations.push(`page exceeds ${merged.maxBytes} byte limit, script tags may be missing`);
  }

  const sources = resolveSources(extractScriptSrc(pageBody.text), page.finalUrl, limitations);

  if (sources.length === 0) {
    limitations.push('no external script tags found');
    return { bundles, limitations };
  }

  if (sources.length > merged.maxBundles) {
    limitations.push(`${sources.length} script tags found, only the first ${merged.maxBundles} analysed`);
  }

  const selected = sources.slice(0, merged.maxBundles);

  // Concurrent, because 40 sequential fetches at 10s each blows the 60s budget
  // the Pages Function gives the whole request. maxBundles already bounds fan-out.
  const results = await Promise.all(selected.map((src) => analyseBundle(src, safeFetch, merged, limitations)));

  for (const bundle of results) {
    if (bundle) bundles.push(bundle);
  }

  const failed = results.filter((r) => r === null).length;
  if (failed) {
    limitations.push(`${failed} of ${selected.length} bundles could not be analysed`);
  }

  return { bundles, limitations };
}