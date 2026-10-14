import { test } from 'node:test';
import assert from 'node:assert/strict';

// This test lives in frontend/test/, NOT next to its module: Pages Functions
// compiles everything under functions/ into the Worker bundle, and a file
// importing node:test would break the deploy. Deliberate deviation from the
// "test next to module" convention (AGENTS.md) for that reason.
import { validateUrl, isDeniedIp, normalizeAddresses, DENYLIST_CIDRS } from '../../functions/api/analyze.js';

// The adapter holds the other copy of the denylist and of the IP arithmetic.
// Importing it here is what makes the parity check below real rather than
// decorative — integration.test.js already imports across this boundary, so it
// is an established pattern and safe under node --test.
import {
  DENYLIST_CIDRS as ADAPTER_CIDRS,
  isDeniedIp as adapterIsDeniedIp,
} from '../../vm-adapter/lib/urlGuard.js';

// PLAN.md 7 fixes this list. Pinning it separately catches the case the pairwise
// check cannot: both copies being edited together, away from the spec.
const SPEC_CIDRS = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16', // link-local + cloud metadata
  '0.0.0.0/8',
  '::1/128',
  'fc00::/7',
];

// The Workers runtime has no /etc/hosts to lean on and the tests must not hit
// live DNS, so every hostname case resolves through this fake seam
// (dependency injection — AGENTS.md testing).
const fakeDns = (map) => ({
  all: async (host) => {
    if (map[host]) return map[host];
    throw new Error(`ENOTFOUND ${host}`);
  },
});

test('the edge denylist matches the adapter denylist', () => {
  // Compared against the adapter's actual export. An earlier version of this
  // assertion compared against a literal in this file, which only pinned the edge
  // copy: editing vm-adapter/lib/urlGuard.js alone would have passed.
  assert.deepEqual(DENYLIST_CIDRS, ADAPTER_CIDRS);
});

test('both denylists still match the ranges PLAN.md 7 fixes', () => {
  assert.deepEqual(DENYLIST_CIDRS, SPEC_CIDRS);
  assert.deepEqual(ADAPTER_CIDRS, SPEC_CIDRS);
});

// The lists agreeing does not prove the two independent implementations agree.
// This is the check that would catch one side learning a new encoding rule.
test('both guards reach the same verdict across encodings and shapes', () => {
  const corpus = [
    '127.0.0.1', '127.1.2.3', '10.0.0.1', '10.255.255.255', '172.15.255.255', '172.16.0.1',
    '172.31.255.255', '172.32.0.1', '192.168.1.1', '169.254.169.254', '169.254.0.1', '0.0.0.0',
    '0.255.255.255', '8.8.8.8', '1.1.1.1', '93.184.216.34', '255.255.255.255',
    '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
    '::ffff:8.8.8.8', '::127.0.0.1', '::169.254.169.254', '::8.8.8.8',
    '2606:4700::1111', '2001:4860:4860::8888', 'ff02::1',
    'not-an-ip', '', '999.1.1.1', '1.2.3', '1.2.3.4.5', '::gggg',
  ];
  const disagreement = corpus.filter((ip) => isDeniedIp(ip) !== adapterIsDeniedIp(ip));
  assert.deepEqual(disagreement, [], `guards disagree on: ${disagreement.join(', ')}`);
});

// Leading-zero octets are the one place the two used to differ: this side parsed
// them as decimal, node:net rejects them outright. Neither is reachable through
// validateUrl, which only ever sees a WHATWG-canonical host, but the predicates
// are exported so the contract is pinned rather than left to chance.
test('non-canonical IPv4 literals get the same answer from both guards', () => {
  for (const ip of ['010.0.0.1', '127.0.0.01', '0177.0.0.1', '00.0.0.0']) {
    assert.equal(isDeniedIp(ip), adapterIsDeniedIp(ip), `guards disagree on ${ip}`);
  }
});

test('a canonicalised URL never reaches the guard non-canonically', () => {
  // Why the disagreement above is latent rather than a live hole.
  assert.equal(new URL('http://010.0.0.1/').hostname, '8.0.0.1');
  assert.equal(new URL('http://0177.0.0.1/').hostname, '127.0.0.1');
  assert.equal(new URL('http://2130706433/').hostname, '127.0.0.1');
});

test('private and metadata IPs are denied without DNS', async () => {
  const cases = [
    'http://127.0.0.1/',
    'http://127.1.2.3/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
    'http://172.31.255.255/',
    'http://192.168.1.1/',
    'http://169.254.169.254/', // cloud metadata
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://[fc00::1]/',
    'http://[::ffff:127.0.0.1]/', // IPv4-mapped
    'http://[::ffff:169.254.169.254]/',
    'http://[::0.0.0.1]/', // IPv4-compatible (deprecated form)
  ];
  for (const url of cases) {
    const check = await validateUrl(url, fakeDns({}));
    assert.equal(check.ok, false, `${url} should be refused`);
    assert.match(check.reason, /blocked|private/);
  }
});

test('non-http schemes are blocked', async () => {
  for (const url of ['file:///etc/passwd', 'ftp://example.com/', 'gopher://example.com/', 'ws://example.com/']) {
    const check = await validateUrl(url, fakeDns({}));
    assert.equal(check.ok, false, `${url} should be refused`);
    assert.match(check.reason, /scheme/);
  }
});

test('a hostname resolving to a private IP is blocked', async () => {
  const check = await validateUrl('https://rebind.test/', fakeDns({
    'rebind.test': ['93.184.216.34', '10.0.0.5'],
  }));
  assert.equal(check.ok, false);
  assert.match(check.reason, /resolves to private IP 10\.0\.0\.5/);
});

test('a hostname resolving only to public IPs passes', async () => {
  const check = await validateUrl('https://example.com/path?q=1', fakeDns({
    'example.com': ['93.184.216.34'],
  }));
  assert.equal(check.ok, true);
  assert.equal(check.url.toString(), 'https://example.com/path?q=1');
});

test('dns failure is refused, not assumed safe', async () => {
  const check = await validateUrl('https://nx.test/', fakeDns({}));
  assert.equal(check.ok, false);
  assert.match(check.reason, /dns resolution failed/);
});

test('an unparseable URL is refused', async () => {
  for (const url of ['not a url', '', null, undefined, 42]) {
    const check = await validateUrl(url, fakeDns({}));
    assert.equal(check.ok, false, `${String(url)} should be refused`);
  }
});

test('isDeniedIp handles boundary addresses', () => {
  assert.equal(isDeniedIp('127.0.0.0'), true);
  assert.equal(isDeniedIp('127.255.255.255'), true);
  assert.equal(isDeniedIp('128.0.0.0'), false);
  assert.equal(isDeniedIp('172.15.255.255'), false);
  assert.equal(isDeniedIp('172.16.0.0'), true);
  assert.equal(isDeniedIp('172.32.0.0'), false);
  assert.equal(isDeniedIp('169.254.169.254'), true);
  assert.equal(isDeniedIp('::1'), true);
  // fe80::/10 (v6 link-local) is absent from BOTH denylists by parity — if it
  // ever gets added here it must be added in vm-adapter/lib/urlGuard.js too.
  assert.equal(isDeniedIp('fe80::1'), false);
  assert.equal(isDeniedIp('fd00::1'), true); // fc00::/7 covers fd00
  assert.equal(isDeniedIp('not-an-ip'), false);
  assert.equal(isDeniedIp(''), false);
});

test('resolve4/resolve6 string records are checked, not dropped', async () => {
  // The real resolvers return bare strings — [{address}] is the lookup shape.
  // If strings were mapped to undefined, isDeniedIp(undefined) is false and a
  // private answer would sail through. This test pins both shapes.
  assert.deepEqual(
    normalizeAddresses(['10.0.0.5', { address: '93.184.216.34' }, undefined, '', 42]),
    ['10.0.0.5', '93.184.216.34'],
  );

  // End-to-end through validateUrl with the string shape a real resolve4 gives.
  const check = await validateUrl('https://stringshape.test/', {
    all: async () => ['10.0.0.5'],
  });
  assert.equal(check.ok, false);
  assert.match(check.reason, /resolves to private IP 10\.0\.0\.5/);
});
