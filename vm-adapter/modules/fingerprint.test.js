import { test } from 'node:test';
import assert from 'node:assert/strict';

import { fingerprint } from './fingerprint.js';

// Both seams are injected — safeFetch for HTTP, probeTls for the certificate.
// With these stubs the suite opens no socket and resolves nothing, so it stays
// deterministic offline. fingerprint() still defaults both to urlGuard.
function stubTls(tls) {
  const calls = [];
  const fn = async (hostname, port) => {
    calls.push({ hostname, port });
    return tls ? { ok: true, tls } : { ok: false, reason: 'tls probe stubbed off' };
  };
  fn.calls = calls;
  return fn;
}

const TLS_FIXTURE = {
  issuer: 'R3',
  subject: 'example.com',
  expiry: 'Dec 31 23:59:59 2026 GMT',
  validFrom: null,
  protocol: 'TLSv1.3',
};

function mockSafeFetch(body, { headers = {}, status = 200, finalUrl = 'https://example.com/' } = {}) {
  const calls = [];
  const fn = async (url) => {
    calls.push(url);
    return {
      ok: true,
      response: new Response(body, { status, headers }),
      finalUrl,
    };
  };
  fn.calls = calls;
  return fn;
}

function blocked(reason) {
  return async () => ({ ok: false, reason });
}

test('reads the Server header as an observation', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html></html>', {
    headers: { server: 'nginx/1.24.0' },
  }), stubTls(TLS_FIXTURE));

  const server = f.findings.find((x) => x.key === 'server');
  assert.equal(server.value, 'nginx/1.24.0');
  assert.equal(server.type, 'observation');
  assert.equal(server.confidence, 'high');
  assert.match(server.evidence, /Server response header/);
});

test('records certificate issuer and expiry from the TLS probe', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html></html>'), stubTls(TLS_FIXTURE));

  const issuer = f.findings.find((x) => x.key === 'tls_issuer');
  const expiry = f.findings.find((x) => x.key === 'tls_expiry');
  assert.equal(issuer.value, 'R3');
  assert.equal(issuer.type, 'observation');
  assert.equal(expiry.value, 'Dec 31 23:59:59 2026 GMT');
  assert.equal(f.tls.issuer, 'R3');
});

test('a failed TLS probe becomes a limitation, never a throw', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html></html>'), stubTls(null));
  assert.equal(f.tls, null);
  assert.match(f.limitations.join(' '), /tls probe failed/);
});

test('the TLS probe is called with the resolved host and port', async () => {
  const probe = stubTls(TLS_FIXTURE);
  await fingerprint('https://example.com/', mockSafeFetch('<html></html>'), probe);
  assert.deepEqual(probe.calls, [{ hostname: 'example.com', port: 443 }]);
});

test('infers framework from an HTML marker as a derivation, not an observation', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch(
    '<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>',
  ), stubTls(TLS_FIXTURE));

  const fw = f.findings.filter((x) => x.key === 'framework');
  assert.ok(fw.length > 0);
  assert.ok(fw.every((x) => x.type === 'derivation'));
  assert.ok(fw.some((x) => x.value === 'Next.js' && x.confidence === 'medium'));
  assert.match(fw[0].evidence, /__NEXT_DATA__/);
});

// A library name in markup is weak evidence — "react-dom" appears in error text
// and CDN references on sites with no React at all, so it must not read as medium.
test('weak framework markers only support a low confidence reading', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch(
    '<html><script src="/x/react-dom.production.min.js"></script></html>',
  ), stubTls(TLS_FIXTURE));

  const fw = f.findings.filter((x) => x.key === 'framework');
  assert.equal(fw.length, 0, 'react-dom alone must not produce a React finding');

  const vue = await fingerprint('https://example.com/', mockSafeFetch(
    '<div data-v-app></div>',
  ), stubTls(TLS_FIXTURE));
  const vueFinding = vue.findings.find((x) => x.key === 'framework');
  assert.equal(vueFinding.value, 'Vue');
  assert.equal(vueFinding.confidence, 'low');
});

test('detects several frameworks from distinct markers', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch(
    '<html><script id="__NEXT_DATA__"></script><div class="wp-content"></div></html>',
  ), stubTls(TLS_FIXTURE));
  const names = f.findings.filter((x) => x.key === 'framework').map((x) => x.value);
  assert.ok(names.includes('Next.js'));
  assert.ok(names.includes('WordPress'));
});

test('detects CDN from a response header and reports which header', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html></html>', {
    headers: { 'cf-ray': '8a1b2c3d4e5f6789-SYD' },
  }), stubTls(TLS_FIXTURE));

  assert.equal(f.cdn, 'Cloudflare');
  const cdnFinding = f.findings.find((x) => x.key === 'cdn');
  assert.equal(cdnFinding.evidence, 'cf-ray response header');
});

test('detects CDN from the Server header when no CDN header is present', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html></html>', {
    headers: { server: 'cloudflare' },
  }), stubTls(TLS_FIXTURE));
  assert.equal(f.cdn, 'Cloudflare');
});

test('records a limitation when safeFetch refuses the URL', async () => {
  const f = await fingerprint('http://127.0.0.1/', blocked('url blocked: resolves to private IP 127.0.0.1'), stubTls(TLS_FIXTURE));

  assert.equal(f.findings.length, 0);
  assert.equal(f.cdn, null);
  assert.equal(f.tls, null);
  assert.match(f.limitations[0], /url blocked: resolves to private IP/);
});

test('a failed fetch never throws — it degrades to a limitation', async () => {
  const f = await fingerprint('https://example.com/', blocked('timeout after 10000ms'), stubTls(TLS_FIXTURE));
  assert.equal(f.findings.length, 0);
  assert.match(f.limitations[0], /timeout/);
});

test('plain http targets report the missing certificate as a limitation', async () => {
  const f = await fingerprint('http://example.com/', mockSafeFetch('<html></html>', {
    finalUrl: 'http://example.com/',
  }), stubTls(TLS_FIXTURE));
  assert.equal(f.tls, null);
  assert.match(f.limitations.join(' '), /not https/);
});

test('no framework marker is a limitation, not a silent omission', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html><body>hi</body></html>'), stubTls(TLS_FIXTURE));
  assert.equal(f.findings.filter((x) => x.key === 'framework').length, 0);
  assert.match(f.limitations.join(' '), /no framework markers/);
});

test('reads the URL through the injected guard rather than importing it', async () => {
  const safeFetch = mockSafeFetch('<html></html>');
  await fingerprint('https://example.com/', safeFetch, stubTls(TLS_FIXTURE));
  assert.deepEqual(safeFetch.calls, ['https://example.com/']);
});

test('every finding carries the full evidence shape', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch(
    '<html><script id="__NEXT_DATA__"></script></html>',
    { headers: { server: 'nginx', 'x-powered-by': 'Express' } },
  ), stubTls(TLS_FIXTURE));

  for (const item of f.findings) {
    for (const key of ['key', 'value', 'type', 'evidence', 'confidence']) {
      assert.ok(item[key] !== undefined && item[key] !== null, `${item.key} missing ${key}`);
    }
    assert.ok(['observation', 'derivation', 'inference'].includes(item.type));
    assert.ok(['high', 'medium', 'low'].includes(item.confidence));
  }
});

test('an error page is disclosed — headers are real but the body is not a normal document', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('<html>404</html>', {
    status: 404,
    headers: { server: 'nginx' },
  }), stubTls(TLS_FIXTURE));

  assert.ok(f.findings.some((x) => x.key === 'server'), 'the server header is still a real observation');
  assert.match(f.limitations.join(' '), /HTTP 404/);
});

test('body reads are capped so a target cannot stream unbounded data in', async () => {
  const huge = 'x'.repeat(4 * 1024 * 1024);
  const f = await fingerprint('https://example.com/', mockSafeFetch(huge), stubTls(TLS_FIXTURE));
  // The cap only bounds memory; the finding must still complete rather than throw.
  assert.ok(Array.isArray(f.findings));
});

// When the cap fires, markers further down the document were never in scope, so
// saying nothing would present a partial scan as a complete one.
test('a truncated body is disclosed as a limitation', async () => {
  const f = await fingerprint('https://example.com/', mockSafeFetch('a'.repeat(2 * 1024 * 1024)), stubTls(TLS_FIXTURE));
  assert.match(f.limitations.join(' '), /truncated at 524288 bytes/);
});