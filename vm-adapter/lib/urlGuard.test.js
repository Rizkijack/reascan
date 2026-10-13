import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DENYLIST_CIDRS, ipInCidr, isDeniedIp, validateUrl } from './urlGuard.js';

test('ipInCidr matches IPv4 ranges', () => {
  assert.equal(ipInCidr('10.1.2.3', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('11.1.2.3', '10.0.0.0/8'), false);
  assert.equal(ipInCidr('1.2.3.4', '0.0.0.0/0'), true);
  assert.equal(ipInCidr('1.2.3.4', '1.2.3.4/32'), true);
  assert.equal(ipInCidr('1.2.3.5', '1.2.3.4/32'), false);
});

test('ipInCidr respects non-byte-aligned prefixes', () => {
  // 172.16.0.0/12 spans 172.16.0.0 – 172.31.255.255
  assert.equal(ipInCidr('172.16.0.0', '172.16.0.0/12'), true);
  assert.equal(ipInCidr('172.31.255.255', '172.16.0.0/12'), true);
  assert.equal(ipInCidr('172.15.255.255', '172.16.0.0/12'), false);
  assert.equal(ipInCidr('172.32.0.0', '172.16.0.0/12'), false);
  assert.equal(ipInCidr('fd00::1', 'fc00::/7'), true);
  assert.equal(ipInCidr('fe80::1', 'fc00::/7'), false);
});

test('ipInCidr rejects mixed families and malformed input', () => {
  assert.equal(ipInCidr('::1', '127.0.0.0/8'), false);
  assert.equal(ipInCidr('10.0.0.1', '::1/128'), false);
  assert.equal(ipInCidr('not-an-ip', '10.0.0.0/8'), false);
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.0'), false);
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.0/33'), false);
});

test('loopback and private ranges are denied', () => {
  for (const ip of ['127.0.0.1', '127.1.2.3', '10.0.0.1', '10.255.255.255',
    '172.16.0.1', '172.20.10.5', '192.168.0.1', '0.0.0.0']) {
    assert.equal(isDeniedIp(ip), true, `${ip} should be denied`);
  }
});

test('cloud metadata address is denied', () => {
  assert.equal(isDeniedIp('169.254.169.254'), true);
  assert.equal(isDeniedIp('169.254.1.1'), true);
});

test('IPv6 loopback and unique-local are denied', () => {
  assert.equal(isDeniedIp('::1'), true);
  assert.equal(isDeniedIp('fc00::1'), true);
  assert.equal(isDeniedIp('fd12:3456::1'), true);
});

test('IPv4-mapped IPv6 literals cannot smuggle a private address', () => {
  assert.equal(isDeniedIp('::ffff:127.0.0.1'), true);
  assert.equal(isDeniedIp('::ffff:169.254.169.254'), true);
  assert.equal(isDeniedIp('::ffff:10.0.0.1'), true);
  assert.equal(isDeniedIp('::ffff:8.8.8.8'), false);
});

// RFC 4291 deprecated IPv4-compatible form. OS stacks still route it to the
// IPv4 address, so it reaches loopback and metadata exactly like ::ffff: does.
test('IPv4-compatible IPv6 literals cannot smuggle a private address', () => {
  assert.equal(isDeniedIp('::127.0.0.1'), true);
  assert.equal(isDeniedIp('::169.254.169.254'), true);
  assert.equal(isDeniedIp('::10.0.0.1'), true);
  assert.equal(isDeniedIp('::8.8.8.8'), false);
});

test('alternate IPv4 encodings are normalised before the denylist sees them', async () => {
  // WHATWG URL collapses these to 127.0.0.1, so the guard must still refuse them.
  for (const raw of ['http://2130706433/', 'http://0177.0.0.1/',
    'http://0x7f.0.0.1/', 'http://127.1/', 'http://[::1]/', 'http://[fd00::1]/']) {
    const result = await validateUrl(raw);
    assert.equal(result.ok, false, `${raw} should be rejected`);
  }
});

test('public addresses are not denied', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1',
    '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isDeniedIp(ip), false, `${ip} should be allowed`);
  }
});

test('DENYLIST_CIDRS covers the ranges PLAN.md 7 requires', () => {
  for (const cidr of ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '169.254.0.0/16', '0.0.0.0/8', '::1/128', 'fc00::/7']) {
    assert.ok(DENYLIST_CIDRS.includes(cidr), `${cidr} missing from denylist`);
  }
});

test('validateUrl rejects non-http schemes', async () => {
  for (const raw of ['file:///etc/passwd', 'gopher://127.0.0.1/', 'ftp://example.com/',
    'data:text/html,hi']) {
    const result = await validateUrl(raw);
    assert.equal(result.ok, false, `${raw} should be rejected`);
  }
});

test('validateUrl rejects unparseable input', async () => {
  assert.equal((await validateUrl('not a url')).ok, false);
  assert.equal((await validateUrl('')).ok, false);
});

test('validateUrl rejects a host that resolves to loopback', async () => {
  const result = await validateUrl('http://localhost/');
  assert.equal(result.ok, false);
  assert.match(result.reason, /private IP|dns resolution failed/);
});