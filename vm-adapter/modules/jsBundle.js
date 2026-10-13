// JS bundle inventory — what the page loads, whether sourcemaps are published,
// what endpoint strings appear in the code, and whether it looks obfuscated.
//
// safeFetch is injected so tests stay offline and this module cannot open a
// socket on its own. Every bundle that fails, times out or exceeds a limit is
// written into limitations — a partial inventory is reported as partial, never as
// a complete one.
//
// No secret-pattern detection here. AGENTS.md is explicit: do not infer secrecy
// from names or text patterns. Endpoints are reported as strings that appear in
// the code, nothing more.

const DEFAULT_LIMITS = {
  maxBundles: 40,
  maxBytes: 1048576,
  timeoutMs: 10000,
  concurrency: 6,
  maxPageBytes: 4 * 1024 * 1024,
};

// Only the src matters; inline scripts have no separate file to fetch.
const SCRIPT_SRC = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;

// Quoted strings shaped like API paths. Kept deliberately narrow — a loose match
// turns a minified bundle into thousands of garbage endpoints.
const ENDPOINT_PATTERNS = [
  /["'`](\/(?:api|v\d+)\/[A-Za-z0-9_\-./{}:$?&=]{1,80})["'`]/g,
  /["'`](https?:\/\/[A-Za-z0-9.\-]+\/(?:api|v\d+)\/[A-Za-z0-9_\-./{}:$?&=]{1,80})["'`]/g,
];

const MAX_ENDPOINTS_PER_BUNDLE = 50;

// Strong signals only. Whole-bundle entropy was rejected: a minified bundle is
// high-entropy by construction, so that check fires on essentially every real
// site and tells the reader nothing.
const OBFUSCATION_SIGNALS = [
  { name: 'eval(atob(', re: /eval\s*\(\s*atob\s*\(/ },
  { name: 'eval(unatob(', re: /eval\s*\(\s*window\.atob\s*\(/ },
  { name: 'packer signature', re: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/ },
  { name: 'base64 blob', re: /["'`][A-Za-z0-9+/]{200,}={0,2}["'`]/ },
];

// Cap the read so a hostile bundle cannot stream unbounded data into the adapter.
async function readCapped(response, maxBytes) {
  if (!response.body) return { text: '', bytes: 0, truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.length;
    chunks.push(value);
    if (bytes >= maxBytes) {
      truncated = true;
      await reader.cancel();
      break;
    }
  }
  return {
    text: Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8'),
    bytes: Math.min(bytes, maxBytes),
    truncated,
  };
}

function extractScripts(html, baseUrl) {
  const found = [];
  const seen = new Set();

  for (const match of html.matchAll(SCRIPT_SRC)) {
    const raw = (match[1] || match[2] || match[3] || '').trim();
    if (!raw) continue;

    let absolute;
    try {
      absolute = new URL(raw, baseUrl).toString();
    } catch {
      continue;
    }

    // data: and blob: are inline payloads, not fetchable bundles.
    if (!absolute.startsWith('http:') && !absolute.startsWith('https:')) continue;
    if (seen.has(absolute)) continue;
    seen.add(absolute);
    found.push(absolute);
  }

  return found;
}

function extractEndpoints(js) {
  const endpoints = new Set();
  for (const pattern of ENDPOINT_PATTERNS) {
    for (const match of js.matchAll(pattern)) {
      endpoints.add(match[1]);
      if (endpoints.size >= MAX_ENDPOINTS_PER_BUNDLE) return [...endpoints];
    }
  }
  return [...endpoints];
}

function detectObfuscation(js) {
  return OBFUSCATION_SIGNALS.filter((s) => s.re.test(js)).map((s) => s.name);
}

async function analyzeOne(src, safeFetch, limits, limitations) {
  const fetched = await safeFetch(src, { timeoutMs: limits.timeoutMs });
  if (!fetched.ok) {
    limitations.push(`${src} — not analysed: ${fetched.reason}`);
    return null;
  }

  const { response } = fetched;
  if (!response.ok) {
    limitations.push(`${src} — not analysed: HTTP ${response.status}`);
    return null;
  }

  const { text, bytes, truncated } = await readCapped(response, limits.maxBytes);
  if (truncated) {
    limitations.push(`${src} — truncated at ${limits.maxBytes} bytes; content past the cap was not analysed`);
  }

  const hits = detectObfuscation(text);

  return {
    src,
    // size_bytes is the exact figure; size_kb is rounded for display and reads
    // 0.0 for anything under ~50 bytes, so it alone cannot back the claim.
    size_bytes: bytes,
    size_kb: Math.round((bytes / 1024) * 10) / 10,
    sourcemap: /\/\/#\s*sourceMappingURL\s*=/.test(text),
    endpoints: extractEndpoints(text),
    obfuscated: hits.length > 0,
    obfuscation_signals: hits,
  };
}

// The exported function is the boundary: a target must never be able to make it
// reject. safeFetch is contractually non-throwing, but a defensive catch keeps a
// hostile target from turning a partial report into a dead request.
export async function analyzeBundles(url, safeFetch, limits = {}) {
  try {
    return await collect(url, safeFetch, limits);
  } catch (err) {
    return { bundles: [], limitations: [`analysis aborted: ${err.message}`] };
  }
}

async function collect(url, safeFetch, limits) {
  const cfg = { ...DEFAULT_LIMITS, ...limits };
  const limitations = [];

  const page = await safeFetch(url, { timeoutMs: cfg.timeoutMs });
  if (!page.ok) {
    limitations.push(`page fetch failed: ${page.reason}`);
    return { bundles: [], limitations };
  }
  if (!page.response.ok) {
    limitations.push(`page fetch returned HTTP ${page.response.status}`);
    return { bundles: [], limitations };
  }

  // Capped for the same reason as each bundle: the entry document is attacker-
// controlled too, and a target that never closes the connection would otherwise
// stream until the adapter runs out of memory.
const html = (await readCapped(page.response, cfg.maxPageBytes)).text;
  const scripts = extractScripts(html, page.finalUrl);

  if (scripts.length === 0) {
    limitations.push('no external <script src> found on the page');
  }

  const overflow = scripts.length - cfg.maxBundles;
  const queue = scripts.slice(0, cfg.maxBundles);
  if (overflow > 0) {
    limitations.push(`${overflow} further <script src> entries not analysed — maxBundles limit is ${cfg.maxBundles}`);
  }

  const bundles = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      const src = queue[cursor++];
      // Caught per bundle: one target that resets the socket must not discard
      // the bundles that were fetched successfully.
      try {
        const result = await analyzeOne(src, safeFetch, cfg, limitations);
        if (result) bundles.push(result);
      } catch (err) {
        limitations.push(`${src} — not analysed: ${err.message}`);
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(cfg.concurrency, queue.length) }, worker));

  limitations.sort();
  return { bundles, limitations };
}