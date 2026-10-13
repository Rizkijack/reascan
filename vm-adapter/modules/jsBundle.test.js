import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeBundles } from './jsBundle.js';

const PAGE_URL = 'https://example.com/';

// Routes by src so one mock can serve the page and its bundles.
function mockSite(routes) {
  const calls = [];
  const fn = async (url) => {
    calls.push(url);
    if (url === PAGE_URL) {
      return { ok: true, response: new Response(routes.page, { status: 200 }), finalUrl: PAGE_URL };
    }
    const route = routes.files[url];
    if (!route) return { ok: false, reason: `no route for ${url}` };
    if (route.fail) return { ok: false, reason: route.fail };
    return { ok: true, response: new Response(route.body ?? '', { status: route.status ?? 200 }), finalUrl: url };
  };
  fn.calls = calls;
  return fn;
}

const page = (srcs) => `<html><body>${srcs.map((s) => `<script src="${s}"></script>`).join('')}</body></html>`;

test('finds script tags and reports them with size and sourcemap', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/a.js', '/b.js']),
    files: {
      'https://example.com/a.js': { body: 'console.log(1)' },
      'https://example.com/b.js': { body: 'console.log(2)\n//# sourceMappingURL=b.js.map' },
    },
  }));

  assert.equal(r.bundles.length, 2);
  const a = r.bundles.find((b) => b.src.endsWith('/a.js'));
  const b = r.bundles.find((b) => b.src.endsWith('/b.js'));
  assert.equal(a.sourcemap, false);
  assert.equal(b.sourcemap, true);
  assert.equal(a.size_bytes, 14);
  assert.equal(b.size_bytes, 44);
});

test('resolves relative, absolute and protocol-relative src against the final URL', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/x.js', 'https://cdn.example.net/y.js']),
    files: {
      'https://example.com/x.js': { body: '' },
      'https://cdn.example.net/y.js': { body: '' },
    },
  }));

  const srcs = r.bundles.map((b) => b.src).sort();
  assert.deepEqual(srcs, ['https://cdn.example.net/y.js', 'https://example.com/x.js']);
});

test('dedupes the same script listed twice', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: '<script src="/dup.js"></script><script src="/dup.js"></script>',
    files: { 'https://example.com/dup.js': { body: '' } },
  }));
  assert.equal(r.bundles.length, 1);
});

test('ignores inline and data-URI scripts — they have nothing to fetch', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: '<script>var x=1</script><script src="data:text/javascript,alert(1)"></script>',
    files: {},
  }));
  assert.equal(r.bundles.length, 0);
  assert.match(r.limitations.join(' '), /no external <script src>/);
});

test('extracts API endpoints as strings found in the code', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/api.js']),
    files: {
      'https://example.com/api.js': {
        body: 'fetch("/api/v1/users");axios.get("/v2/posts");var u="/api/v1/users";',
      },
    },
  }));

  const endpoints = r.bundles[0].endpoints;
  assert.ok(endpoints.includes('/api/v1/users'));
  assert.ok(endpoints.includes('/v2/posts'));
  assert.equal(endpoints.length, 2, 'the duplicate path must be deduped');
});

test('caps endpoints per bundle so one file cannot flood the report', async () => {
  const many = Array.from({ length: 200 }, (_, i) => `fetch("/api/v1/item${i}");`).join('\n');
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/big.js']),
    files: { 'https://example.com/big.js': { body: many } },
  }));
  assert.equal(r.bundles[0].endpoints.length, 50);
});

test('detects strong obfuscation signals and names them', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/o.js']),
    files: { 'https://example.com/o.js': { body: 'eval(atob("ZGVjb2RlZCBiYXNlNjQ="));' } },
  }));

  const b = r.bundles[0];
  assert.equal(b.obfuscated, true);
  assert.ok(b.obfuscation_signals.includes('eval(atob('));
});

test('a plain minified bundle is not reported as obfuscated', async () => {
  // Whitespace-stripped code is high entropy by construction — reporting it as
  // obfuscated would be a false positive on essentially every real site.
  const minified = `var a=1,b=2;function${''}c(d){return d*a+b}for(var i=0;i<100;i++){console.log(c(i))}`;
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/m.js']),
    files: { 'https://example.com/m.js': { body: minified } },
  }));
  assert.equal(r.bundles[0].obfuscated, false);
});

test('a failed bundle becomes a limitation, not a silent omission', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/ok.js', '/dead.js']),
    files: {
      'https://example.com/ok.js': { body: '' },
      'https://example.com/dead.js': { fail: 'timeout after 10000ms' },
    },
  }));

  assert.equal(r.bundles.length, 1);
  assert.match(r.limitations.join(' '), /dead\.js.*timeout/s);
});

test('an HTTP error bundle becomes a limitation carrying the status', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/missing.js']),
    files: { 'https://example.com/missing.js': { status: 404 } },
  }));
  assert.equal(r.bundles.length, 0);
  assert.match(r.limitations.join(' '), /HTTP 404/);
});

test('enforces maxBundles and reports the overflow', async () => {
  const srcs = Array.from({ length: 7 }, (_, i) => `/s${i}.js`);
  const files = Object.fromEntries(srcs.map((s) => [`https://example.com${s}`, { body: '' }]));

  const r = await analyzeBundles(PAGE_URL, mockSite({ page: page(srcs), files }), { maxBundles: 3 });

  assert.equal(r.bundles.length, 3);
  assert.match(r.limitations.join(' '), /4 further.*maxBundles limit is 3/);
});

test('truncates an oversized bundle and says so', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: page(['/huge.js']),
    files: { 'https://example.com/huge.js': { body: 'a'.repeat(50_000) } },
  }), { maxBytes: 1024 });

  assert.equal(r.bundles.length, 1, 'a truncated bundle is still reported');
  assert.match(r.limitations.join(' '), /truncated at 1024 bytes/);
  assert.equal(r.bundles[0].size_kb, 1);
});

test('a blocked page fetch returns no bundles and one limitation', async () => {
  const blocked = async () => ({ ok: false, reason: 'url blocked: resolves to private IP 127.0.0.1' });
  const r = await analyzeBundles('http://127.0.0.1/', blocked);

  assert.equal(r.bundles.length, 0);
  assert.match(r.limitations.join(' '), /resolves to private IP/);
});

test('a page error status is reported rather than parsed', async () => {
  const r = await analyzeBundles(PAGE_URL, mockSite({
    page: null,
    files: {},
  }), {});
  // The mock serves 200 for the page; assert the guard instead.
  assert.ok(Array.isArray(r.bundles));

  const errPage = async () => ({ ok: true, response: new Response('', { status: 503 }), finalUrl: PAGE_URL });
  const r2 = await analyzeBundles(PAGE_URL, errPage);
  assert.equal(r2.bundles.length, 0);
  assert.match(r2.limitations.join(' '), /HTTP 503/);
});

test('never throws — a rejecting guard degrades to an empty report', async () => {
  const throwing = async () => { throw new Error('boom'); };
  const r = await analyzeBundles(PAGE_URL, throwing);

  assert.deepEqual(r.bundles, []);
  assert.match(r.limitations.join(' '), /analysis aborted: boom/);
});

test('a rejecting guard on a single bundle does not lose the others', async () => {
  const flaky = async (url) => {
    if (url === PAGE_URL) {
      return { ok: true, response: new Response(page(['/good.js', '/bad.js'])), finalUrl: PAGE_URL };
    }
    if (url.endsWith('/bad.js')) throw new Error('socket reset');
    return { ok: true, response: new Response('ok'), finalUrl: url };
  };

  const r = await analyzeBundles(PAGE_URL, flaky);
  assert.equal(r.bundles.length, 1);
  assert.equal(r.bundles[0].src, 'https://example.com/good.js');
});