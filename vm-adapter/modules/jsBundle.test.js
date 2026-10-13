import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeBundles, DEFAULT_LIMITS } from './jsBundle.js';

// A fake target: a page plus a set of bundles keyed by absolute URL. safeFetch is
// the only way this module can reach anything, so stubbing it makes the suite
// fully offline.
function fakeTarget(pageHtml, bundles = {}, { fail = new Set(), pageFails = false } = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    if (pageFails) return { ok: false, reason: 'timeout after 10000ms' };

    const html = pageHtml;
    if (url === 'https://target.test/' || url === 'https://target.test') {
      return { ok: true, response: new Response(html, { status: 200 }), finalUrl: 'https://target.test/' };
    }
    if (fail.has(url)) return { ok: false, reason: 'url blocked: resolves to private IP 10.0.0.5' };
    if (url in bundles) {
      return { ok: true, response: new Response(bundles[url], { status: 200 }), finalUrl: url };
    }
    return { ok: false, reason: 'fetch failed: 404' };
  };
  fn.calls = calls;
  return fn;
}

test('finds script tags and reports size', async () => {
  const target = fakeTarget(
    '<html><script src="/static/app.js"></script></html>',
    { 'https://target.test/static/app.js': 'console.log(1)' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles.length, 1);
  assert.equal(bundles[0].src, 'https://target.test/static/app.js');
  assert.equal(bundles[0].size_kb, 0);
  assert.equal(bundles[0].sourcemap, false);
});

test('resolves relative and protocol-relative sources, deduplicates', async () => {
  const target = fakeTarget(
    '<html>'
    + '<script src="/a.js"></script>'
    + '<script src="a.js"></script>'
    + '<script src="https://cdn.test/b.js"></script>'
    + '<script src="data:text/javascript,1"></script>'
    + '</html>',
    { 'https://target.test/a.js': 'x', 'https://cdn.test/b.js': 'y' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  const srcs = bundles.map((b) => b.src);
  assert.deepEqual(srcs.sort(), ['https://cdn.test/b.js', 'https://target.test/a.js']);
});

test('resolves relative sources against the page we landed on, not the URL requested', async () => {
  // A root-relative "/app.js" resolves to the root either way, so the src has to
  // be genuinely relative for this to tell the two base URLs apart.
  const fn = async (url) => {
    if (url === 'https://target.test/') {
      return {
        ok: true,
        response: new Response('<script src="app.js"></script>'),
        finalUrl: 'https://target.test/redirected/',
      };
    }
    return { ok: true, response: new Response('ok'), finalUrl: url };
  };

  const { bundles } = await analyzeBundles('https://target.test/', fn);
  assert.equal(bundles[0].src, 'https://target.test/redirected/app.js');
});

test('detects a sourcemap comment as an observation', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': 'code\n//# sourceMappingURL=app.js.map\n' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles[0].sourcemap, true);
});

test('extracts API-shaped path literals and skips static assets', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    {
      'https://target.test/app.js': [
        'fetch("/api/v1/users")',
        'x("/graphql")',
        'y("/static/logo.png")',
        'z("/app.js")',
        'fetch("/api/v1/users")',
      ].join('\n'),
    },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  assert.deepEqual(bundles[0].endpoints, ['/api/v1/users', '/graphql']);
});

test('flags obfuscation signatures', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': 'eval(atob("payload"))' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles[0].obfuscated, true);
  assert.equal(bundles[0].obfuscation_marker, 'eval(atob(');
});

test('plain code is not flagged as obfuscated', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': 'function add(a,b){return a+b}' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles[0].obfuscated, false);
  assert.equal(bundles[0].obfuscation_marker, undefined);
});

test('a failed bundle becomes a limitation, not a missing row', async () => {
  const target = fakeTarget(
    '<script src="/a.js"></script><script src="/b.js"></script>',
    { 'https://target.test/a.js': 'ok' },
    { fail: new Set(['https://target.test/b.js']) },
  );

  const { bundles, limitations } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles.length, 1);
  assert.match(limitations.join(' '), /b\.js: url blocked/);
  assert.match(limitations.join(' '), /1 of 2 bundles could not be analysed/);
});

test('a page that cannot be fetched degrades to a limitation', async () => {
  const target = fakeTarget('', {}, { pageFails: true });
  const { bundles, limitations } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles.length, 0);
  assert.match(limitations[0], /page fetch failed/);
});

test('exceeding maxBytes is reported as a limitation', async () => {
  const target = fakeTarget(
    '<script src="/big.js"></script>',
    { 'https://target.test/big.js': 'x'.repeat(5000) },
  );

  const { bundles, limitations } = await analyzeBundles('https://target.test/', target, { maxBytes: 1000 });
  assert.match(limitations.join(' '), /exceeds 1000 byte limit/);
  assert.ok(bundles[0].size_kb <= 1);
});

test('exceeding maxBundles is reported and the rest are skipped', async () => {
  const tags = Array.from({ length: 5 }, (_, i) => `<script src="/s${i}.js"></script>`).join('');
  const target = fakeTarget(tags);

  const { bundles, limitations } = await analyzeBundles('https://target.test/', target, { maxBundles: 2 });
  assert.equal(bundles.length, 0);
  assert.match(limitations.join(' '), /5 script tags found, only the first 2 analysed/);
});

test('a page with no scripts reports that as a limitation', async () => {
  const target = fakeTarget('<html><body>plain</body></html>');
  const { bundles, limitations } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles.length, 0);
  assert.match(limitations.join(' '), /no external script tags/);
});

test('endpoint lists are capped and the cap is disclosed', async () => {
  const many = Array.from({ length: 40 }, (_, i) => `"/api/v${i}/thing"`).join('\n');
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': many },
  );

  const { bundles, limitations } = await analyzeBundles('https://target.test/', target);
  assert.equal(bundles[0].endpoints.length, 25);
  assert.match(limitations.join(' '), /endpoint list capped at 25/);
});

test('timeoutMs is passed through to every fetch', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': 'ok' },
  );

  await analyzeBundles('https://target.test/', target, { timeoutMs: 2500 });
  assert.ok(target.calls.length >= 2);
  assert.ok(target.calls.every((c) => c.opts?.timeoutMs === 2500));
});

test('default limits match AGENTS.md', () => {
  assert.equal(DEFAULT_LIMITS.maxBundles, 40);
  assert.equal(DEFAULT_LIMITS.maxBytes, 1048576);
  assert.equal(DEFAULT_LIMITS.timeoutMs, 10000);
});

test('reports nothing about secrets — only the endpoint literals themselves', async () => {
  const target = fakeTarget(
    '<script src="/app.js"></script>',
    { 'https://target.test/app.js': 'fetch("/api/config"); var API_KEY = "sk-live-abc123";' },
  );

  const { bundles } = await analyzeBundles('https://target.test/', target);
  const serialised = JSON.stringify(bundles);
  assert.deepEqual(bundles[0].endpoints, ['/api/config']);
  assert.ok(!serialised.includes('sk-live-abc123'), 'bundle values must never be echoed back');
});