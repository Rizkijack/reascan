// End-to-end smoke test: step 1 -> step 6 as one chain.
//
//   urlGuard (1) -> fingerprint (2) / jsBundle (3) -> adapter server (4)
//   -> Pages Function edge guard (6) -> findings
//
// Step 5 (install.sh) is exercised separately because it needs a shell.
//
// No mocks in the happy path: a real adapter is booted on an ephemeral port and
// the real edge handler dials it over HTTP, so this walks the same route the
// deployed system will.
//
// Lives at the repo root because its imports are root-relative
// (./vm-adapter/..., ./frontend/...): run it as `node smoke-e2e.mjs`.

import { createAdapter } from './vm-adapter/server.js';
import { validateUrl, safeFetch, isDeniedIp } from './vm-adapter/lib/urlGuard.js';
import { fingerprint } from './vm-adapter/modules/fingerprint.js';
import { analyzeBundles } from './vm-adapter/modules/jsBundle.js';
import { onRequestPost } from './frontend/functions/api/analyze.js';

const KEY = 'smoke-test-key-0123456789abcdef';
const TARGET = 'https://example.com/';

let pass = 0;
let fail = 0;
const ok = (m) => { pass++; console.log(`  ok    ${m}`); };
const bad = (m) => { fail++; console.log(`  FAIL  ${m}`); };
const section = (m) => console.log(`\n== ${m} ==`);

// ---------------------------------------------------------------- step 1
section('step 1 - urlGuard (SSRF guard)');
for (const ip of ['127.0.0.1', '10.1.1.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', '::127.0.0.1']) {
  isDeniedIp(ip) ? ok(`denied ${ip}`) : bad(`NOT denied ${ip}`);
}
for (const ip of ['8.8.8.8', '1.1.1.1', '::ffff:8.8.8.8']) {
  !isDeniedIp(ip) ? ok(`allowed ${ip}`) : bad(`wrongly denied ${ip}`);
}
for (const raw of ['file:///etc/passwd', 'gopher://x/', 'http://127.1/']) {
  const r = await validateUrl(raw);
  !r.ok ? ok(`refused ${raw}`) : bad(`NOT refused ${raw}`);
}
const live = await validateUrl(TARGET);
live.ok ? ok(`resolves a public target (${live.url.hostname})`) : bad(`public target refused: ${live.reason}`);

// ---------------------------------------------------------------- steps 2-3
section('steps 2-3 - analysis modules, live against a real host');
const fp = await fingerprint(TARGET, safeFetch);
fp.findings.length > 0 ? ok(`fingerprint produced ${fp.findings.length} findings`) : bad('fingerprint produced nothing');
const shaped = fp.findings.every((f) => f.key && f.value !== undefined && f.type && f.evidence && f.confidence);
shaped ? ok('every finding carries key/value/type/evidence/confidence') : bad('a finding is missing part of the evidence shape');
Array.isArray(fp.limitations) ? ok(`fingerprint reports ${fp.limitations.length} limitation(s)`) : bad('no limitations array');

const jb = await analyzeBundles(TARGET, safeFetch);
Array.isArray(jb.bundles) ? ok(`jsBundle returned ${jb.bundles.length} bundle(s), ${jb.limitations.length} limitation(s)`) : bad('jsBundle shape wrong');

// ---------------------------------------------------------------- step 4
section('step 4 - adapter server over real HTTP');
const server = createAdapter({ API_KEY: KEY });
await new Promise((res) => server.listen(0, '127.0.0.1', res));
const base = `http://127.0.0.1:${server.address().port}`;
try {
  const noKey = await fetch(`${base}/health`);
  noKey.status === 401 ? ok('no key -> 401') : bad(`no key -> ${noKey.status}`);

  const health = await fetch(`${base}/health`, { headers: { 'x-api-key': KEY } });
  const healthBody = await health.json();
  health.status === 200 && healthBody.status === 'ok'
    ? ok(`health ok, tools: ${healthBody.tools_available.join(', ')}`)
    : bad(`health returned ${health.status}`);

  const blockedPost = await fetch(`${base}/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({ url: 'http://169.254.169.254/' }),
  });
  blockedPost.status === 422 ? ok('metadata URL -> 422') : bad(`metadata URL -> ${blockedPost.status}`);

  // ------------------------------------------------------------- step 6
  section('step 6 - Pages Function edge guard, dialling the live adapter');
  const ctx = (body) => ({
    request: new Request('https://reascan.pages.dev/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env: { VM_ADAPTER_URL: base, API_KEY: KEY },
  });

  const edgeBlocked = await onRequestPost(ctx({ url: 'http://127.0.0.1/' }));
  edgeBlocked.status === 422 ? ok('edge refuses loopback -> 422') : bad(`edge loopback -> ${edgeBlocked.status}`);

  const unconfigured = await onRequestPost({
    request: new Request('https://x/api/analyze', { method: 'POST', body: '{}' }),
    env: {},
  });
  unconfigured.status === 500 || unconfigured.status === 422
    ? ok(`unconfigured/empty env -> ${unconfigured.status}`)
    : bad(`unconfigured env -> ${unconfigured.status}`);

  const unreachable = await onRequestPost({
    request: new Request('https://x/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: TARGET }),
    }),
    env: { VM_ADAPTER_URL: 'http://127.0.0.1:1', API_KEY: KEY },
  });
  unreachable.status === 502 ? ok('dead engine -> 502') : bad(`dead engine -> ${unreachable.status}`);

  const end = await onRequestPost(ctx({ url: TARGET, categories: ['fingerprint'] }));
  const endBody = await end.json();
  if (end.status === 200 && endBody.status === 'done') {
    ok(`END-TO-END ok - url=${endBody.findings.url} findings=${endBody.findings.fingerprint.findings.length} confidence=${endBody.findings.verdict.confidence}`);
    const v = endBody.findings.verdict;
    Array.isArray(v.limitations) && Array.isArray(v.unknowns)
      ? ok(`verdict carries ${v.limitations.length} limitation(s), ${v.unknowns.length} unknown(s)`)
      : bad('verdict missing limitations/unknowns');
  } else {
    bad(`END-TO-END failed: ${end.status} ${JSON.stringify(endBody).slice(0, 160)}`);
  }
} finally {
  await new Promise((r) => server.close(r));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
