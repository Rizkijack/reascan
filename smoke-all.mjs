// Comprehensive local smoke test: every feature of steps 1-7, minus the parts
// that require a VM (cloudflared, systemd, a real tunnel).
//
//   step 1  lib/urlGuard.js          SSRF guard: CIDR math, DNS, redirect hops, TLS
//   step 2  modules/fingerprint.js   headers/framework/CDN/TLS + limitations
//   step 3  modules/jsBundle.js      script inventory, endpoints, limits, isolation
//   step 4  server.js                auth, routing, body errors, verdict, deadline
//   step 5  install.sh / reaMcp.js   .env bootstrap (shell), phase-2 stub contract
//   step 6  frontend/                edge guard, proxy, health, and app.js in a DOM shim
//   step 7  invariants               denylist parity, no bypass, no score, no secrets
//
// Network is used only where the guard itself is the thing under test (real DNS,
// real TLS, the live example.com analysis). Everything else runs on injected
// dependencies or a local server, so the run is deterministic.
//
// Run: node smoke-all.mjs

import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { isDeniedIp, ipInCidr, validateUrl, resolvePublic, safeFetch, safeTlsInfo, DENYLIST_CIDRS } from './vm-adapter/lib/urlGuard.js';
import { readCapped } from './vm-adapter/lib/body.js';
import { fingerprint } from './vm-adapter/modules/fingerprint.js';
import { analyzeBundles } from './vm-adapter/modules/jsBundle.js';
import { createAdapter } from './vm-adapter/server.js';
import { callReaTool, REA_MCP_ENABLED, REA_TOOLS } from './vm-adapter/lib/reaMcp.js';
import { onRequestPost, validateUrl as edgeValidateUrl, DENYLIST_CIDRS as EDGE_CIDRS, normalizeAddresses } from './functions/api/analyze.js';
import { onRequestGet as healthGet } from './functions/api/health.js';

// ---------------------------------------------------------------- harness
let total = 0;
let failed = 0;
let skipped = 0;
let stepFails = [];
let currentStep = '';
const section = (s) => { console.log(`\n== ${s} ==`); currentStep = s; };
const check = (name, cond, detail = '') => {
  total++;
  if (cond) { console.log(`  ok    ${name}`); return; }
  failed++;
  stepFails.push(`${currentStep} :: ${name}`);
  console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
};
const group = (name) => console.log(`  -- ${name}`);
// A check that cannot run is not a pass and not a failure. Counting it as either
// would misreport the suite: omitted silently it inflates confidence, counted as
// FAIL it blames the code for a missing interpreter.
const skip = (name, why) => { skipped++; console.log(`  skip  ${name} — ${why}`); };

// ---------------------------------------------------------------- shell
// install.sh is bash. On Windows that means Git Bash, which is not on PATH by
// default, so a bare execFileSync('bash') throws ENOENT and takes the whole run
// down with it — the step 5 checks never execute and the crash reads as a broken
// tool rather than a result.
//
// Windows restores ProgramFiles in every child process, so the no-bash branch
// cannot be provoked by clearing the environment. Candidates and the probe are
// therefore parameters, which lets the same run assert that the fallback really
// returns null instead of leaving it to inspection.
function bashCandidates(env = process.env) {
  const out = [];
  if (process.platform === 'win32') {
    for (const root of [env.ProgramFiles, env['ProgramFiles(x86)'], env.LOCALAPPDATA]) {
      if (root) out.push(join(root, 'Git', 'bin', 'bash.exe'), join(root, 'Programs', 'Git', 'bin', 'bash.exe'));
    }
  }
  out.push('bash');
  return out;
}

function probeBash(bin) {
  try {
    execFileSync(bin, ['-c', 'exit 0'], { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false; // ENOENT (absent) or non-zero (broken) — not usable either way
  }
}

function resolveBash(candidates = bashCandidates(), probe = probeBash) {
  for (const bin of candidates) if (probe(bin)) return bin;
  return null;
}
const BASH = resolveBash();

// ---------------------------------------------------------------- helpers
const mkSafeFetch = (map) => async (url) => {
  const key = String(url);
  const entry = map[key];
  if (entry === undefined) return { ok: false, reason: `not in fixture: ${key}` };
  if (entry === 'THROW') throw new Error('socket reset by peer');
  return {
    ok: true,
    response: new Response(entry.body ?? '', { status: entry.status ?? 200, headers: entry.headers ?? {} }),
    finalUrl: entry.finalUrl ?? key,
  };
};

// ================================================================ STEP 1
section('step 1 — lib/urlGuard.js (SSRF guard)');

group('CIDR arithmetic (pure, offline)');
check('loopback is inside 127.0.0.0/8', ipInCidr('127.9.9.9', '127.0.0.0/8'));
check('128.0.0.0 is outside 127.0.0.0/8', !ipInCidr('128.0.0.0', '127.0.0.0/8'));
check('172.16.0.0/12 boundary in', ipInCidr('172.16.0.0', '172.16.0.0/12'));
check('172.32.0.0 outside 172.16.0.0/12', !ipInCidr('172.32.0.0', '172.16.0.0/12'));
check('fd00::1 inside fc00::/7', ipInCidr('fd00::1', 'fc00::/7'));
check('v4 and v6 never mix', !ipInCidr('127.0.0.1', '::1/128'));

group('denylist verdicts');
for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.5.5', '192.168.1.1', '169.254.169.254', '0.0.0.0', '::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1', '::127.0.0.1']) {
  check(`denied ${ip}`, isDeniedIp(ip));
}
for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946', '::ffff:8.8.8.8']) {
  check(`allowed ${ip}`, !isDeniedIp(ip));
}
check('garbage is not an IP', !isDeniedIp('not-an-ip') && !isDeniedIp('') && !isDeniedIp(undefined));

group('validateUrl (scheme + literal + DNS)');
for (const raw of ['file:///etc/passwd', 'gopher://x/', 'ftp://x/', 'ws://x/']) {
  const r = await validateUrl(raw);
  check(`refuses scheme in ${raw}`, !r.ok && /scheme/.test(r.reason), r.reason);
}
for (const raw of ['http://127.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data/']) {
  const r = await validateUrl(raw);
  check(`refuses literal ${raw}`, !r.ok, r.reason);
}
check('refuses unparseable input', !(await validateUrl('not a url')).ok);
check('refuses a host that does not resolve', !(await validateUrl('https://no-such-host.invalid/')).ok);
check('accepts a real public host (live DNS)', (await validateUrl('https://example.com/')).ok);

group('resolvePublic (live DNS)');
{
  const good = await resolvePublic('example.com');
  check('resolves and returns addresses', good.ok && good.addresses.length > 0);
  const bad = await resolvePublic('localhost');
  check('refuses a private answer', !bad.ok, bad.reason);
}

group('safeFetch (live, redirects handled manually)');
{
  const direct = await safeFetch('https://example.com/');
  check('fetches a public URL', direct.ok && direct.finalUrl.startsWith('https://example.com/'), direct.reason);

  const blocked = await safeFetch('http://169.254.169.254/');
  check('refuses the metadata address before dialling', !blocked.ok, blocked.reason);

  // A live open redirector asking for metadata — the exact hop attack the guard
  // exists for. It must refuse (or fail), never land on the metadata address.
  const hop = await safeFetch('https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/');
  check('refuses a redirect into link-local space', !hop.ok, hop.reason ?? 'it followed the hop!');

  const timeout = await safeFetch('https://example.com/', { timeoutMs: 1 });
  check('aborts at the timeout', !timeout.ok && /timeout/.test(timeout.reason), timeout.reason);
}

group('safeTlsInfo (live)');
{
  const tls = await safeTlsInfo('example.com');
  check('reads the presented certificate', tls.ok && !!tls.tls.issuer, tls.reason);
  const refused = await safeTlsInfo('localhost');
  check('refuses a private host', !refused.ok, refused.reason);
}

group('body.js bounded reads');
{
  const big = new Response('x'.repeat(5000));
  const capped = await readCapped(big, 100);
  check('caps the body', capped.bytes === 100 && capped.truncated === true && capped.text.length === 100);

  const small = await readCapped(new Response('hello'), 100);
  check('passes a small body through', small.bytes === 5 && small.truncated === false);
  check('handles a bodyless response', (await readCapped(new Response(null), 10)).bytes === 0);
}

// ================================================================ STEP 2
section('step 2 — modules/fingerprint.js');

group('observations straight from headers');
{
  const fp = await fingerprint('https://t.test/', mkSafeFetch({
    'https://t.test/': { headers: { server: 'nginx/1.25', 'x-powered-by': 'Express' } },
  }));
  const byKey = Object.fromEntries(fp.findings.map((f) => [f.key, f]));
  check('server header becomes a finding', byKey.server?.value === 'nginx/1.25' && byKey.server.type === 'observation' && byKey.server.confidence === 'high');
  check('x-powered-by is an observation', byKey.powered_by?.value === 'Express' && byKey.powered_by.confidence === 'high');
  check('framework implied by powered_by is high confidence', fp.findings.some((f) => f.key === 'framework' && f.value === 'Express' && f.confidence === 'high'));
  check('every finding carries evidence', fp.findings.every((f) => typeof f.evidence === 'string' && f.evidence.length > 0));
}

group('framework markers follow marker strength');
{
  const next = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { body: '<html>__NEXT_DATA__</html>' } }));
  check('__NEXT_DATA__ -> Next.js at medium', next.findings.some((f) => f.key === 'framework' && f.value === 'Next.js' && f.confidence === 'medium' && f.type === 'derivation'));

  const react = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { body: '<div data-reactroot></div>' } }));
  check('data-reactroot -> React at low', react.findings.some((f) => f.key === 'framework' && f.value === 'React' && f.confidence === 'low'));
}

group('CDN detection');
{
  const cf = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { headers: { 'cf-ray': 'abc123' } } }));
  check('cf-ray -> Cloudflare', cf.cdn === 'Cloudflare' && cf.findings.some((f) => f.key === 'cdn'));

  const cfServer = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { headers: { server: 'cloudflare' } } }));
  check('server: cloudflare is also detected', cfServer.cdn === 'Cloudflare');
}

group('TLS through an injected probe (offline)');
{
  const fp = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': {} }), async () => ({
    ok: true, tls: { issuer: 'Test CA', subject: 't.test', expiry: 'Jan 1 2030', validFrom: 'Jan 1 2020', protocol: 'TLSv1.3' },
  }));
  check('tls issuer/expiry become findings', fp.findings.some((f) => f.key === 'tls_issuer') && fp.findings.some((f) => f.key === 'tls_expiry'));
  check('tls block is returned for rendering', fp.tls?.protocol === 'TLSv1.3');
}

group('failures become limitations, never fake findings');
{
  const dead = await fingerprint('https://t.test/', async () => ({ ok: false, reason: 'timeout after 10000ms' }));
  check('fetch failure -> limitation, no findings', dead.findings.length === 0 && dead.limitations.some((l) => /http fetch failed/.test(l)));
  check('tls stays null when the fetch failed', dead.tls === null);

  const err = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { status: 500, headers: { server: 'nginx' }, body: '<html>error</html>' } }));
  check('error page is disclosed as a limitation', err.limitations.some((l) => /HTTP 500/.test(l)));
  check('headers are still reported from an error response', err.findings.some((f) => f.key === 'server'));

  const plain = await fingerprint('http://t.test/', mkSafeFetch({ 'http://t.test/': { body: '<html></html>' } }));
  check('non-https -> limitation, no TLS claim', plain.limitations.some((l) => /not https/.test(l)));

  const big = await fingerprint('https://t.test/', mkSafeFetch({ 'https://t.test/': { body: 'a'.repeat(600 * 1024) } }));
  check('body over the cap is declared', big.limitations.some((l) => /truncated/.test(l)));
}

// ================================================================ STEP 3
section('step 3 — modules/jsBundle.js');

const PAGE = 'https://t.test/';
const pageWith = (scripts) => ({ body: `<html>${scripts.map((s) => `<script src="${s}"></script>`).join('')}</html>` });

group('script discovery');
{
  const r = await analyzeBundles(PAGE, mkSafeFetch({
    [PAGE]: pageWith(['/a.js', '/a.js', 'https://cdn.test/b.js', 'data:text/javascript,void(0)', 'blob:https://t.test/x']),
    'https://t.test/a.js': { body: 'console.log(1)' },
    'https://cdn.test/b.js': { body: 'console.log(2)' },
  }));
  check('resolves relative srcs and dedupes', r.bundles.length === 2 && r.bundles.some((b) => b.src === 'https://t.test/a.js'));
  check('skips data: and blob: payloads', !r.bundles.some((b) => /^(data|blob):/.test(b.src)));
  check('absolute cdn src kept', r.bundles.some((b) => b.src === 'https://cdn.test/b.js'));
}

group('per-bundle analysis');
{
  const body = 'fetch("/api/v1/users");axios.get("/v2/posts");get("https://api.test/api/x");\n//# sourceMappingURL=app.js.map';
  const r = await analyzeBundles(PAGE, mkSafeFetch({ [PAGE]: pageWith(['/app.js']), 'https://t.test/app.js': { body } }));
  const b = r.bundles[0];
  check('size_bytes is exact and size_kb derived', b.size_bytes === Buffer.byteLength(body) && typeof b.size_kb === 'number');
  check('sourcemap comment detected', b.sourcemap === true);
  check('endpoints extracted and deduped', b.endpoints.includes('/api/v1/users') && b.endpoints.includes('/v2/posts') && b.endpoints.includes('https://api.test/api/x'), JSON.stringify(b.endpoints));
  check('not obfuscated', b.obfuscated === false);
}

group('obfuscation signals (strong ones only)');
{
  const evalAtob = await analyzeBundles(PAGE, mkSafeFetch({ [PAGE]: pageWith(['/o.js']), 'https://t.test/o.js': { body: 'eval(atob("ZWNobyBoaQ=="))' } }));
  check('eval(atob( flagged', evalAtob.bundles[0].obfuscated === true && evalAtob.bundles[0].obfuscation_signals.includes('eval(atob('));

  const minified = await analyzeBundles(PAGE, mkSafeFetch({ [PAGE]: pageWith(['/m.js']), 'https://t.test/m.js': { body: 'var a=1,b=2;for(var i=0;i<9;i++){a+=i*b}' } }));
  check('plain minified code is NOT called obfuscated', minified.bundles[0].obfuscated === false);
}

group('limits are reported, not silent');
{
  const scripts = Array.from({ length: 45 }, (_, i) => `/s${i}.js`);
  const map = { [PAGE]: pageWith(scripts) };
  for (const s of scripts) map[`https://t.test${s}`] = { body: 'x' };
  const r = await analyzeBundles(PAGE, mkSafeFetch(map), { maxBundles: 5 });
  check('maxBundles caps the count', r.bundles.length === 5);
  check('the overflow is declared', r.limitations.some((l) => /40|not analysed/.test(l) || /maxBundles/.test(l)), JSON.stringify(r.limitations.slice(0, 2)));

  const big = await analyzeBundles(PAGE, mkSafeFetch({ [PAGE]: pageWith(['/big.js']), 'https://t.test/big.js': { body: 'y'.repeat(2048) } }), { maxBytes: 512 });
  check('maxBytes truncation is declared', big.limitations.some((l) => /truncated/.test(l)));
  check('reported size reflects what was kept', big.bundles[0].size_bytes === 512);

  const none = await analyzeBundles(PAGE, mkSafeFetch({ [PAGE]: { body: '<html>no scripts</html>' } }));
  check('no scripts -> limitation', none.bundles.length === 0 && none.limitations.some((l) => /no external <script/.test(l)));
}

group('failure isolation and hostile safety');
{
  const r = await analyzeBundles(PAGE, mkSafeFetch({
    [PAGE]: pageWith(['/ok.js', '/boom.js', '/500.js']),
    'https://t.test/ok.js': { body: 'ok' },
    'https://t.test/boom.js': 'THROW',
    'https://t.test/500.js': { status: 503, body: 'down' },
  }));
  check('one broken bundle does not discard the others', r.bundles.length === 1 && r.bundles[0].src === 'https://t.test/ok.js');
  check('the thrower is reported', r.limitations.some((l) => /boom\.js/.test(l)));
  check('the 503 is reported', r.limitations.some((l) => /500\.js.*503/.test(l)));

  const hostile = await analyzeBundles(PAGE, async () => { throw new Error('page fetch exploded'); });
  check('analyzeBundles never rejects', Array.isArray(hostile.bundles) && hostile.limitations.some((l) => /aborted/.test(l)));
}

// ================================================================ STEP 4
section('step 4 — server.js over real HTTP');

const KEY = 'smoke-key-0123456789abcdef';
const server = createAdapter({ API_KEY: KEY });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const post = (body, headers = {}) => fetch(`${base}/analyze`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-api-key': KEY, ...headers },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

try {
  group('auth is checked before routing');
  check('no key -> 401', (await fetch(`${base}/health`)).status === 401);
  check('wrong key -> 401', (await fetch(`${base}/health`, { headers: { 'x-api-key': 'nope' } })).status === 401);
  check('key of a different length -> 401, no crash', (await fetch(`${base}/analyze`, { method: 'POST', headers: { 'x-api-key': 'short' } })).status === 401);
  check('correct key -> 200', (await fetch(`${base}/health`, { headers: { 'x-api-key': KEY } })).status === 200);

  group('routing');
  // Deliberately structural rather than a pinned literal: the capability list grows
  // whenever an adapter gains a mode, and pinning the exact array turns every such
  // addition into a test edit — which is how a contract test becomes a rubber stamp.
  // (This check was a literal, and that is exactly why it broke on the REA wiring.)
  const health = await (await fetch(`${base}/health`, { headers: { 'x-api-key': KEY } })).json();
  check('/health reports ok', health.status === 'ok');
  check('/health advertises every base capability',
    ['fingerprint', 'jsBundle', 'browserCapture', 'jsDeep'].every((t) => health.tools_available.includes(t)),
    JSON.stringify(health.tools_available));
  // rea_tools must be read from the module, not kept as a second hardcoded copy in
  // server.js — this is the one place an operator sees what the VM can serve.
  check('/health echoes the live REA catalogue',
    JSON.stringify(health.rea_tools) === JSON.stringify(REA_TOOLS),
    JSON.stringify(health.rea_tools));
  check('unknown path -> 404', (await fetch(`${base}/nope`, { headers: { 'x-api-key': KEY } })).status === 404);
  check('wrong method -> 404', (await fetch(`${base}/analyze`, { headers: { 'x-api-key': KEY } })).status === 404);

  group('body and URL validation');
  check('malformed JSON -> 422', (await post('not json')).status === 422);
  check('oversized body -> 422', (await post({ url: 'https://example.com/', pad: 'z'.repeat(9000) })).status === 422);
  check('blocked URL -> 422', (await post({ url: 'http://169.254.169.254/' })).status === 422);

  group('categories select work');
  {
    const onlyFp = await (await post({ url: 'https://example.com/', categories: ['fingerprint'] })).json();
    check('fingerprint-only run skips bundles', onlyFp.findings.js_bundles.length === 0);
    const unknown = await post({ url: 'https://example.com/', categories: ['nonsense'] });
    const unknownBody = await unknown.json();
    check('unknown category -> low confidence, not an error', unknown.status === 200 && unknownBody.findings.verdict.confidence === 'low');
  }

  group('verdict aggregation');
  {
    const r = await (await post({ url: 'https://example.com/', categories: ['fingerprint', 'jsBundle'] })).json();
    check('verdict has confidence/limitations/unknowns', ['high', 'medium', 'low'].includes(r.findings.verdict.confidence) && Array.isArray(r.findings.verdict.limitations) && Array.isArray(r.findings.verdict.unknowns));
    check('cdn present -> origin unknown is raised', r.findings.verdict.unknowns.some((u) => /origin server is not observable/i.test(u)));
    check('live analysis finds something', r.findings.fingerprint.findings.length > 0);
    check('duration_ms reported', typeof r.duration_ms === 'number');
  }

  group('every response is JSON with a status field');
  {
    const probes = [
      await fetch(`${base}/health`),
      await post('bad'),
      await post({ url: 'http://127.0.0.1/' }),
      await fetch(`${base}/nope`, { headers: { 'x-api-key': KEY } }),
    ];
    let allJson = true;
    for (const p of probes) {
      const ct = p.headers.get('content-type') ?? '';
      if (!ct.includes('application/json')) allJson = false;
      const body = await p.json().catch(() => null);
      if (!body || !['ok', 'error', 'done'].includes(body.status)) allJson = false;
    }
    check('all responses are JSON with a known status', allJson);
  }
} finally {
  await new Promise((r) => server.close(r));
}

// ================================================================ STEP 5
section('step 5 — install.sh / reaMcp.js / .env.example (VM-only parts skipped)');

group('install.sh');
{
  const sh = readFileSync('vm-adapter/install.sh', 'utf8');

  // The resolver's contract, asserted rather than assumed: the no-bash path must
  // yield null (so callers skip), and the first working candidate must win.
  check('bash resolver returns null when nothing works', resolveBash([], () => false) === null);
  check('bash resolver takes the first usable candidate', resolveBash(['a', 'b'], (b) => b === 'b') === 'b');
  check('bash resolver skips broken candidates', resolveBash(['broken', 'good'], (b) => b === 'good') === 'good');
  if (!BASH) skip('resolver found a real bash', 'none on this host — step 5 shell checks below are skipped');

  if (BASH) {
    check('passes a shell syntax check', (() => { try { execFileSync(BASH, ['-n', 'vm-adapter/install.sh']); return true; } catch { return false; } })());
  } else {
    skip('passes a shell syntax check', 'no usable bash (install Git Bash, or run on Linux)');
  }
  check('refuses to run as non-root', /run as root/.test(sh));
  check('never overwrites an existing .env', /if \[ ! -f "\$ADAPTER_DIR\/\.env" \]/.test(sh));
  check('generates the key with node crypto', /randomBytes\(32\)/.test(sh) && /node:crypto/.test(sh));
  check('cloudflared downloads to a temp path first', /CF_TMP="\$\(mktemp\)"/.test(sh));
  check('warns that a quick tunnel hostname rotates', /QUICK tunnel/.test(sh));
  check('is ESM-free shell with strict mode', /set -euo pipefail/.test(sh));

  // The .env block, extracted verbatim and driven with a stubbed log/die.
  const block = sh.slice(sh.indexOf('# --- 1. .env'), sh.indexOf('\nfi', sh.indexOf('# --- 1. .env')) + 3);
  const run = (dir) => {
    // bash here is Git Bash on Windows: a C:\Users\... path must be handed over
    // with forward slashes and quoted, or the backslashes are read as escapes.
    const posix = dir.replace(/\\/g, '/');
    const script = `log() { printf 'log: %s\\n' "$*"; }\ndie() { printf 'die: %s\\n' "$*" >&2; exit 1; }\nADAPTER_DIR="${posix}"\n${block}`;
    return execFileSync(BASH, ['-c', script], { encoding: 'utf8' });
  };

  // Driving the extracted block needs a real shell; without one these are skipped
  // rather than reported, so a Windows box without Git Bash does not silently
  // claim the .env bootstrap was verified.
  if (!BASH) {
    for (const name of ['creates .env with a 64-hex key', 'prints the key once for the operator',
      'a placeholder key is replaced, not shipped', 'a template with no API_KEY line fails loudly',
      'and leaves no stranded .env behind', 'a missing .env.example is refused, not worked around',
      'a missing template still leaves no .env behind', 'the tunnel unit interpolates $PORT rather than a literal']) {
      skip(name, 'no usable bash');
    }
  }
  check('docker-free: no docker in the unit files', !/docker/i.test(sh));
  const tmp = mkdtempSync(join(tmpdir(), 'reascan-env-'));
  try {
    if (!BASH) throw new Error('skip-shell');
    writeFileSync(join(tmp, '.env.example'), 'API_KEY=\nPORT=8787\nHOST=127.0.0.1\n');
    const out = run(tmp);
    const env = readFileSync(join(tmp, '.env'), 'utf8');
    const key = env.match(/^API_KEY=(.+)$/m)?.[1] ?? '';
    check('creates .env with a 64-hex key', /^[0-9a-f]{64}$/.test(key), key.slice(0, 8));
    check('prints the key once for the operator', out.includes(key));

    writeFileSync(join(tmp, '.env.example'), 'API_KEY=change-me\nPORT=8787\n');
    rmSync(join(tmp, '.env'));
    run(tmp);
    check('a placeholder key is replaced, not shipped', !readFileSync(join(tmp, '.env'), 'utf8').includes('change-me'));

    writeFileSync(join(tmp, '.env.example'), 'PORT=8787\n');
    rmSync(join(tmp, '.env'));
    let died = false;
    try { run(tmp); } catch { died = true; }
    check('a template with no API_KEY line fails loudly', died);
    check('and leaves no stranded .env behind', !(() => { try { readFileSync(join(tmp, '.env')); return true; } catch { return false; } })());

    // Regression guard for the case that left a 0-byte .env: the shell creates the
    // destination before sed reads the source, so a missing template used to leave
    // an empty file that every later run then treated as configured.
    rmSync(join(tmp, '.env.example'), { force: true });
    rmSync(join(tmp, '.env'), { force: true });
    let refused = false;
    try { run(tmp); } catch { refused = true; }
    check('a missing .env.example is refused, not worked around', refused);
    check('a missing template still leaves no .env behind', !(() => { try { readFileSync(join(tmp, '.env')); return true; } catch { return false; } })());

    // The tunnel unit must follow PORT out of .env, or the two services drift.
    check('the tunnel unit interpolates $PORT rather than a literal', /\$PORT/.test(sh) && /cloudflared tunnel --url http:\/\/localhost:\$PORT/.test(sh));
  } catch (err) {
    // Only the no-shell signal is expected here; anything else is a real bug and
    // must not be swallowed.
    if (err?.message !== 'skip-shell') throw err;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

group('.env.example');
{
  const env = readFileSync('vm-adapter/.env.example', 'utf8');
  check('declares API_KEY, PORT and HOST', /^API_KEY=/m.test(env) && /^PORT=8787/m.test(env) && /^HOST=127\.0\.0\.1/m.test(env));
  if (BASH) {
    check('sources cleanly in a POSIX shell', execFileSync(BASH, ['-c', `set -a; . vm-adapter/.env.example; [ "$PORT" = 8787 ] && [ "$HOST" = 127.0.0.1 ] && echo yes`], { encoding: 'utf8' }).trim() === 'yes');
  } else {
    skip('sources cleanly in a POSIX shell', 'no usable bash');
  }
}

group('reaMcp.js (phase-2 integration)');
{
  // Previously a stub; the engine is wired now. The invariant that still matters is
  // that what the integration *advertises* matches what it can *dispatch* — a
  // declared-but-unknown tool would be an operator-visible lie on /health.
  check('the REA integration is live, not a stub', REA_MCP_ENABLED === true);
  check('declares the expected tool set', REA_TOOLS.length === 2 && REA_TOOLS.includes('browser.capture') && REA_TOOLS.includes('js.analyzeDeep'), REA_TOOLS.join(','));
  // Called without a url on purpose: the guard short-circuits before any dispatch,
  // so this proves the case is recognised without launching a browser.
  const known = await Promise.all(REA_TOOLS.map((t) => callReaTool(t, {})));
  check('every declared tool is known to the dispatcher', known.every((r) => r.ok === false && !/unknown REA tool/.test(r.reason)), JSON.stringify(known.map((r) => r.reason)));
  const r = await callReaTool('asar.extract', { url: 'https://example.com/' });
  check('an engine-less category fails visibly instead of pretending', r.ok === false && /not installed on this VM/.test(r.reason), r.reason);
  check('an unknown tool is rejected, not silently accepted', (await callReaTool('nope', { url: 'https://example.com/' })).ok === false);
}

// ================================================================ STEP 6
section('step 6 — frontend (edge guard, proxy, health, app.js)');

group('edge guard (offline, injected DNS)');
{
  const dns = (map) => ({ all: async (h) => { if (map[h]) return map[h]; throw new Error(`ENOTFOUND ${h}`); } });
  check('denylist matches the adapter', JSON.stringify(EDGE_CIDRS) === JSON.stringify(DENYLIST_CIDRS));
  check('refuses loopback literal', !(await edgeValidateUrl('http://127.0.0.1/', dns({}))).ok);
  check('refuses metadata literal', !(await edgeValidateUrl('http://169.254.169.254/', dns({}))).ok);
  check('refuses a host resolving private', !(await edgeValidateUrl('https://rebind.test/', dns({ 'rebind.test': ['10.0.0.5'] }))).ok);
  check('accepts a public host', (await edgeValidateUrl('https://ok.test/', dns({ 'ok.test': ['93.184.216.34'] }))).ok);
  check('string-shaped resolver records are honoured', !(await edgeValidateUrl('https://s.test/', dns({ 's.test': ['10.0.0.9'] }))).ok);
  check('normalizeAddresses handles both shapes', JSON.stringify(normalizeAddresses(['1.1.1.1', { address: '2.2.2.2' }, null])) === '["1.1.1.1","2.2.2.2"]');
}

group('edge proxy against a stand-in engine');
{
  const engine = createAdapter({ API_KEY: KEY });
  await new Promise((r) => engine.listen(0, '127.0.0.1', r));
  const base2 = `http://127.0.0.1:${engine.address().port}`;
  const call = (env, body) => onRequestPost({
    request: new Request('https://reascan.pages.dev/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    env,
  });
  try {
    check('blocked URL -> 422 before the engine is called', (await call({ VM_ADAPTER_URL: base2, API_KEY: KEY }, { url: 'http://127.0.0.1/' })).status === 422);
    check('missing engine config -> 500', (await call({}, { url: 'https://example.com/' })).status === 500);
    check('dead engine -> 502', (await call({ VM_ADAPTER_URL: 'http://127.0.0.1:1', API_KEY: KEY }, { url: 'https://example.com/' })).status === 502);
    check('malformed body -> 422', (await onRequestPost({ request: new Request('https://x/', { method: 'POST', body: 'nope' }), env: { VM_ADAPTER_URL: base2, API_KEY: KEY } })).status === 422);

    const ok = await call({ VM_ADAPTER_URL: base2, API_KEY: KEY }, { url: 'https://example.com/', categories: ['fingerprint'] });
    const okBody = await ok.json();
    check('live path returns 200 done', ok.status === 200 && okBody.status === 'done');
    check('findings pass through with evidence', okBody.findings.fingerprint.findings.every((f) => f.evidence && f.confidence));

    // Wrong key against the real adapter: the 401 must be filed as 502.
    const wrong = await call({ VM_ADAPTER_URL: base2, API_KEY: 'wrong-key-000000000000' }, { url: 'https://example.com/' });
    check('engine 401 surfaces as 502', wrong.status === 502);
    check('and the engine reason survives', (await wrong.json()).error === 'unauthorised');
  } finally {
    await new Promise((r) => engine.close(r));
  }
}

group('health.js');
{
  const res = await healthGet();
  check('200 with the documented body', res.status === 200 && JSON.stringify(await res.json()) === '{"status":"ok"}');
  check('needs no context', (await healthGet()).status === 200);
}

group('app.js in a DOM shim (the feature with no unit coverage)');
{
  // Minimal element model: just enough for app.js's createElement/textContent/
  // append/addEventListener usage. It is a shim, not a browser — it proves the
  // wiring and the state machine, not the pixels.
  class El {
    constructor(tag) {
      this.tagName = tag.toUpperCase();
      this.children = [];
      this.handlers = {};
      this._text = '';
      this.className = '';
      this.hidden = false;
      this.disabled = false;
      this.value = '';
      this.type = '';
      this.checked = false;
    }
    get textContent() { return this._text || this.children.map((c) => c.textContent).join(''); }
    set textContent(v) { this._text = String(v ?? ''); this.children = []; }
    append(...nodes) {
      for (const n of nodes) {
        if (typeof n === 'string') { this._text += n; continue; }
        if (n.isFragment) { this.children.push(...n.children); continue; }
        this.children.push(n);
      }
    }
    addEventListener(type, fn) { (this.handlers[type] ??= []).push(fn); }
    scrollIntoView() {}
    fire(type, event = {}) { for (const fn of this.handlers[type] ?? []) fn({ preventDefault() {}, ...event }); }
    get all() { return this.children.flatMap((c) => [c, ...c.all]); }
    querySelector() { return null; }
  }
  const frag = () => ({ isFragment: true, children: [], append(...n) { this.children.push(...n.flatMap((x) => (x?.isFragment ? x.children : [x]))); } });
  const byId = new Map();
  const els = {
    'analyze-form': new El('form'),
    'target-url': new El('input'),
    'analyze-btn': new El('button'),
    'status': new El('p'),
    'results': new El('section'),
    'verdict': new El('div'),
    'findings-body': new El('div'),
    'history-section': new El('section'),
    'history-list': new El('ul'),
    'clear-history': new El('button'),
  };
  const cat = (value, checked) => { const e = new El('input'); e.value = value; e.checked = checked; return e; };
  const categories = [cat('fingerprint', true), cat('jsBundle', true)];
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.document = {
    getElementById: (id) => (els[id] ??= byId.get(id) ?? new El('div')),
    createElement: (tag) => new El(tag),
    createTextNode: (t) => { const e = new El('text'); e.textContent = t; return e; },
    createDocumentFragment: frag,
    querySelectorAll: () => categories,
  };

  let fetchImpl = async () => ({ status: 200, json: async () => ({ status: 'done', findings: FINDINGS }) });
  // Save the real globals: the shim must not leak into the step-7 checks below.
  const realFetch = globalThis.fetch;
  const realDocument = globalThis.document;
  const realLocalStorage = globalThis.localStorage;
  globalThis.fetch = (...a) => fetchImpl(...a);

  const FINDINGS = {
    url: 'https://example.com/',
    timestamp: '2026-10-13T12:00:00.000Z',
    fingerprint: { findings: [{ key: 'server', value: 'nginx', type: 'observation', evidence: 'Server header', confidence: 'high' }], cdn: null, tls: { issuer: 'Test CA', expiry: '2030' } },
    js_bundles: [{ src: 'https://example.com/app.js', size_kb: 12.3, sourcemap: true, endpoints: ['/api/v1/users'], obfuscated: false }],
    verdict: { confidence: 'medium', limitations: ['CDN hides the origin'], unknowns: ['Does /api/v1/users need auth'] },
  };

  await import('./frontend/app.js');
  const form = els['analyze-form'];
  check('boots without throwing and wires the form', (form.handlers.submit ?? []).length === 1);

  els['target-url'].value = 'not a url';
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 5));
  check('invalid URL -> error state', els['status'].className.includes('error') && /valid URL/.test(els['status'].textContent));

  els['target-url'].value = 'https://example.com/';
  fetchImpl = async () => ({ status: 200, json: async () => ({ status: 'done', findings: FINDINGS }) });
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 10));
  check('success path reveals the results panel', els['results'].hidden === false);
  check('verdict badge shows the confidence', els['verdict'].textContent.includes('medium'));
  check('fingerprint row is rendered with its evidence', els['findings-body'].textContent.includes('evidence') || els['findings-body'].all.some((e) => e.textContent.includes('Server header')));
  // Limitations/unknowns are part of the verdict block, not the findings body.
  const verdictText = els['verdict'].textContent;
  check('limitations and unknowns are shown', verdictText.includes('CDN hides the origin') && verdictText.includes('Does /api/v1/users need auth'), verdictText.slice(0, 80));
  check('limitation/unknown counts are labelled', /Limitations \(1\)/.test(verdictText) && /Unknowns \(1\)/.test(verdictText));
  check('bundle endpoints are rendered', els['findings-body'].textContent.includes('/api/v1/users'));
  check('history saved to localStorage', JSON.parse(store.get('reascan:history') ?? '[]').length === 1);
  check('history list is visible with one entry', els['history-section'].hidden === false && els['history-list'].children.length === 1);

  const entryButtons = els['history-list'].children[0].children[0];
  els['results'].hidden = true;
  entryButtons.fire('click');
  check('clicking a history entry re-renders it', els['results'].hidden === false && els['verdict'].textContent.includes('medium'));

  fetchImpl = async () => ({ status: 422, json: async () => ({ status: 'error', error: 'url blocked: resolves to private IP 10.0.0.5' }) });
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 10));
  check('engine error -> error state with the reason', els['status'].className.includes('error') && els['status'].textContent.includes('resolves to private IP'));

  fetchImpl = async () => { throw new Error('network down'); };
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 10));
  check('a thrown fetch is caught, not leaked', els['status'].textContent.includes('could not reach'));

  els['clear-history'].fire('click');
  check('clear history empties storage and hides the panel', store.get('reascan:history') === undefined && els['history-section'].hidden === true);

  // A 200 carrying {status:'done'} with no findings is a contract breach. It used
  // to reach saveToHistory(), throw on findings.url, and surface as "could not
  // reach the analyzer" — blaming the network for a server that answered wrongly.
  fetchImpl = async () => ({ status: 200, json: async () => ({ status: 'done' }) });
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 10));
  check('done-without-findings reads as a contract error, not a network error',
    els['status'].className.includes('error')
      && /no findings/.test(els['status'].textContent)
      && !/could not reach/.test(els['status'].textContent),
    els['status'].textContent.slice(0, 80));

  // Storage refusing the write must not be swallowed: the list would simply stop
  // growing and the user would have no way to tell why.
  const realSetItem = globalThis.localStorage.setItem;
  globalThis.localStorage.setItem = () => { throw new Error('QuotaExceededError'); };
  fetchImpl = async () => ({ status: 200, json: async () => ({ status: 'done', findings: FINDINGS }) });
  form.fire('submit');
  await new Promise((r) => setTimeout(r, 10));
  check('a storage refusal is surfaced in the history panel',
    /too large|kept the newest/.test(els['history-list'].textContent),
    els['history-list'].textContent.slice(0, 90));
  // The notice must carry the class style.css targets, or it renders as if it were
  // an ordinary entry — which is how it looked before the rule was added.
  check('the notice carries the class style.css styles',
    els['history-list'].children.some((li) => String(li.className).includes('history-notice')));
  check('style.css actually defines that class', /\.history-notice\s*\{/.test(readFileSync('frontend/style.css', 'utf8')));
  check('the report still renders when history cannot be written', els['results'].hidden === false);
  globalThis.localStorage.setItem = realSetItem;

  // Hand the real globals back before anything else runs.
  globalThis.fetch = realFetch;
  globalThis.document = realDocument;
  if (realLocalStorage === undefined) delete globalThis.localStorage; else globalThis.localStorage = realLocalStorage;
  check('shim globals are restored', globalThis.fetch === realFetch);

  const html = readFileSync('frontend/index.html', 'utf8');
  const ids = [...html.matchAll(/id="([a-z-]+)"/g)].map((m) => m[1]);
  check('index.html provides every id app.js looks up', Object.keys(els).every((id) => ids.includes(id)), Object.keys(els).filter((id) => !ids.includes(id)).join(','));
  check('app.js renders with textContent only (no innerHTML sink)', !/\.innerHTML\s*=/.test(readFileSync('frontend/app.js', 'utf8')));
  check('style.css is linked and non-trivial', /style\.css/.test(html) && readFileSync('frontend/style.css', 'utf8').length > 2000);
}

// ================================================================ STEP 7
section('step 7 — cross-cutting invariants');

group('security invariants');
{
  const files = [
    'vm-adapter/server.js', 'vm-adapter/lib/urlGuard.js', 'vm-adapter/lib/body.js', 'vm-adapter/lib/reaMcp.js',
    'vm-adapter/modules/fingerprint.js', 'vm-adapter/modules/jsBundle.js',
    'functions/api/analyze.js', 'functions/api/health.js', 'frontend/app.js',
  ];
  const src = Object.fromEntries(files.map((f) => [f, readFileSync(f, 'utf8')]));

  // A raw lowercase fetch( — "safeFetch(" cannot match this because of the
  // capital F, so urlGuard.js is the only adapter file allowed to appear here.
  const rawFetch = files
    .filter((f) => f.startsWith('vm-adapter/'))
    .filter((f) => /(^|[^A-Za-z])fetch\(/.test(src[f]));
  check('urlGuard is the only adapter file calling fetch()', rawFetch.every((f) => f.endsWith('urlGuard.js')), rawFetch.join(','));
  check('analysis modules never call fetch() themselves', !rawFetch.some((f) => f.includes('/modules/')), rawFetch.join(','));

  const edgeFetches = [...src['functions/api/analyze.js'].matchAll(/(^|[^A-Za-z])fetch\(([^\n]*)/g)].map((m) => m[2].trim());
  check('the edge has exactly one fetch(), aimed at the configured engine', edgeFetches.length === 1 && /env\.VM_ADAPTER_URL/.test(edgeFetches[0]), edgeFetches.join(' | '));

  check("safeFetch keeps redirect: 'manual'", /redirect: 'manual'/.test(src['vm-adapter/lib/urlGuard.js']));
  check('redirect hops are capped at 3', /maxRedirects = 3/.test(src['vm-adapter/lib/urlGuard.js']));
  check('TLS dials the checked IP with SNI', /servername: publicHost/.test(src['vm-adapter/lib/urlGuard.js']));
  check('no secret-pattern detection anywhere', !Object.values(src).some((s) => /secret[A-Z_]*(pattern|regex|scan)/i.test(s)));
  check('no numeric score introduced', !Object.values(src).some((s) => /\bscore\b/i.test(s.replace(/\/\/.*$/gm, ''))));
  check('no console.* on a production path', !Object.entries(src).some(([f, s]) => f.endsWith('.js') && /console\.(log|warn|error)/.test(s) && !f.includes('app.js')));
}

group('evidence standard in the shipped shape');
{
  const r = await (async () => {
    const s = createAdapter({ API_KEY: KEY });
    await new Promise((res) => s.listen(0, '127.0.0.1', res));
    try {
      const res = await fetch(`http://127.0.0.1:${s.address().port}/analyze`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': KEY },
        body: JSON.stringify({ url: 'https://example.com/', categories: ['fingerprint', 'jsBundle'] }),
      });
      return (await res.json()).findings;
    } finally { await new Promise((res) => s.close(res)); }
  })();
  const types = new Set(r.fingerprint.findings.map((f) => f.type));
  check('finding types are observation/derivation/inference', [...types].every((t) => ['observation', 'derivation', 'inference'].includes(t)), [...types].join(','));
  check('no finding lacks evidence', r.fingerprint.findings.every((f) => f.evidence));
  check('verdict carries limitations and unknowns arrays', Array.isArray(r.verdict.limitations) && Array.isArray(r.verdict.unknowns));
  check('payload carries no secret values', !JSON.stringify(r).toLowerCase().includes('secret'));
  check('payload carries no numeric score field', !Object.keys(r).includes('score'));
}

// ---------------------------------------------------------------- summary
console.log(`\n${'='.repeat(60)}`);
console.log(`SMOKE RESULT: ${total - failed}/${total} checks passed${skipped ? ` (${skipped} skipped — not run, not silently counted as passing)` : ''}`);
if (failed) {
  console.log(`\nfailed checks:`);
  for (const f of stepFails) console.log(`  - ${f}`);
}
if (skipped) {
  console.log(`\nskipped: ${skipped}. These were NOT verified in this run.`);
}
process.exit(failed === 0 ? 0 : 1);
