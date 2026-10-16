// Tests for the two pure decisions that make browser capture honest: how the
// configured egress proxy is interpreted, and which browser flags that
// interpretation earns. Everything else in reaEnv.js launches real processes
// against a real network, which is the job of the VM, not of a unit test.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseUpstreamProxy, proxyArgsFor } from './reaEnv.js';

// Clear-then-set, not set-in-order: on Windows process.env is case-insensitive,
// so writing `https_proxy` and then "clearing" `HTTPS_PROXY` would delete the
// value that was just assigned and the test would pass for the wrong reason.
const TOUCHED = [
  'https_proxy', 'HTTPS_PROXY',
  'http_proxy', 'HTTP_PROXY',
  'REA_IGNORE_CERT_ERRORS',
];

function withEnv(vars, fn) {
  const prev = new Map(TOUCHED.map((key) => [key, process.env[key]]));
  for (const key of TOUCHED) delete process.env[key];
  for (const [key, value] of Object.entries(vars)) {
    if (value !== undefined) process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const key of TOUCHED) {
      const before = prev.get(key);
      if (before === undefined) delete process.env[key];
      else process.env[key] = before;
    }
  }
}

// The ambient environment on a developer machine may already carry a proxy; a
// test that means "no proxy" has to say so explicitly rather than assume it.
// Spread first so an explicit value in the same literal wins the key.
const NO_PROXY = {
  https_proxy: undefined,
  HTTPS_PROXY: undefined,
  http_proxy: undefined,
  HTTP_PROXY: undefined,
};

test('no proxy configured reads as direct egress, not as an unknown', () => {
  assert.equal(withEnv(NO_PROXY, () => parseUpstreamProxy()), null);
});

test('a credentialed proxy parses into parts the forwarder can inject', () => {
  const parsed = withEnv(
    { ...NO_PROXY, https_proxy: 'http://alice:s3cret@proxy.internal:8080' },
    () => parseUpstreamProxy(),
  );
  assert.deepEqual(parsed, { user: 'alice', pass: 's3cret', host: 'proxy.internal', port: '8080' });
});

test('an uppercase scheme still parses', () => {
  const parsed = withEnv(
    { ...NO_PROXY, https_proxy: 'HTTP://alice:s3cret@proxy.internal:8080' },
    () => parseUpstreamProxy(),
  );
  assert.equal(parsed.host, 'proxy.internal');
});

test('http_proxy is honoured when https_proxy is absent', () => {
  const parsed = withEnv(
    { ...NO_PROXY, http_proxy: 'http://alice:s3cret@proxy.internal:8080' },
    () => parseUpstreamProxy(),
  );
  assert.equal(parsed.port, '8080');
});

test('a proxy with no injectable credentials is opaque, never silently absent', () => {
  // The regression this guards. Reading this as "no proxy" launched a browser
  // with no route and no proxy vars on a proxy-only network; it still started,
  // still captured, and produced a screenshot of an error page that the report
  // would have carried as evidence. An unparseable proxy is a loss of egress and
  // must be reported as one.
  const parsed = withEnv(
    { ...NO_PROXY, https_proxy: 'http://proxy.corp.example:8080' },
    () => parseUpstreamProxy(),
  );
  assert.deepEqual(parsed, { opaque: true });
});

test('a proxy with no port is opaque too', () => {
  const parsed = withEnv(
    { ...NO_PROXY, https_proxy: 'http://alice:s3cret@proxy.internal' },
    () => parseUpstreamProxy(),
  );
  assert.deepEqual(parsed, { opaque: true });
});

test('direct egress gets no proxy flags and no TLS bypass by default', () => {
  const args = withEnv({ REA_IGNORE_CERT_ERRORS: undefined }, () => proxyArgsFor('direct'));
  assert.deepEqual(args, []);
});

test('forwarder mode gets the proxy route and the TLS bypass it needs', () => {
  const args = withEnv({ REA_IGNORE_CERT_ERRORS: undefined }, () => proxyArgsFor('forwarder'));
  assert.ok(args.includes('--ignore-certificate-errors'));
  assert.ok(args.some((a) => a.startsWith('--proxy-server=http://127.0.0.1:')));
  assert.ok(args.includes('--proxy-bypass-list=127.0.0.1,localhost,::1'));
});

test('forwarder mode keeps its bypass even when nothing else is overridden', () => {
  const args = withEnv({ REA_IGNORE_CERT_ERRORS: '1' }, () => proxyArgsFor('forwarder'));
  assert.ok(args.includes('--ignore-certificate-errors'));
  assert.ok(args.some((a) => a.startsWith('--proxy-server=')));
});

test('REA_IGNORE_CERT_ERRORS=1 restores the TLS bypass on direct egress, and nothing else', () => {
  // A self-signed or hostname-mismatched target is a normal target for a tool
  // pointed at hostile infrastructure, so the opt-in has to exist — but it must
  // not also conjure up a proxy route that direct egress does not have.
  const args = withEnv({ REA_IGNORE_CERT_ERRORS: '1' }, () => proxyArgsFor('direct'));
  assert.deepEqual(args, ['--ignore-certificate-errors']);
});