// HTTP/TLS fingerprint — server, framework, CDN, certificate.
//
// Every value carries the evidence it came from. A header value is an
// observation; a framework guessed from an HTML marker is a derivation. Nothing
// here infers secrecy from names — see AGENTS.md.
//
// safeFetch and probeTls are injected so tests drive this module without touching
// the network. Defaults keep the DESIGN.md 3.6 two-argument call working, and both
// defaults are urlGuard functions — no path here reaches a socket unguarded.
import { safeTlsInfo } from '../lib/urlGuard.js';
import { readCapped } from '../lib/body.js';

// Enough of the document to catch framework markers. A larger body costs memory
// and buys nothing; markers live in the first screen of markup.
const MAX_HTML_BYTES = 512 * 1024;

// Confidence follows evidence strength. A dedicated build artefact (__NEXT_DATA__,
// ng-version) is strong evidence of a framework. A library name appearing in a
// page is not — "react-dom" turns up in error text, docs and CDN references on
// sites that have nothing to do with React, so it only supports a low reading.
const FRAMEWORK_MARKERS = [
  { name: 'Next.js', confidence: 'medium', patterns: ['__NEXT_DATA__', '/_next/'] },
  { name: 'Angular', confidence: 'medium', patterns: ['ng-version=', 'ng-app', 'ng-strict-'] },
  { name: 'WordPress', confidence: 'medium', patterns: ['wp-content', 'wp-includes', 'wp-embed'] },
  { name: 'Laravel', confidence: 'medium', patterns: ['laravel_session', 'laravel_token', 'XSRF-TOKEN'] },
  { name: 'Vue', confidence: 'low', patterns: ['data-v-', '__VUE__'] },
  { name: 'React', confidence: 'low', patterns: ['data-reactroot', '__REACT_DEVTOOLS'] },
];

const CDN_MARKERS = [
  { name: 'Cloudflare', headers: ['cf-ray', 'cf-cache-status'], serverMatch: /cloudflare/i },
  { name: 'CloudFront', headers: ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-cf-idempotency-id'] },
  { name: 'Fastly', headers: ['x-served-by', 'x-fastly-request-id', 'fastly-debug-digest'], serverMatch: /fastly/i },
  { name: 'Google', headers: ['x-goog-generation', 'x-guploader-uploadid'], serverMatch: /^(gws|esf|Google Frontend)$/i },
  { name: 'Akamai', headers: ['akamai-grn', 'x-akamai-transformed'], serverMatch: /akamai/i },
];

function finding(key, value, type, evidence, confidence) {
  return { key, value, type, evidence, confidence };
}

function detectCdn(headers, serverHeader) {
  for (const cdn of CDN_MARKERS) {
    const headerHit = cdn.headers.find((h) => headers.get(h));
    if (headerHit) return { name: cdn.name, evidence: `${headerHit} response header` };
    if (cdn.serverMatch && serverHeader && cdn.serverMatch.test(serverHeader)) {
      return { name: cdn.name, evidence: `Server header: ${serverHeader}` };
    }
  }
  return null;
}

function detectFramework(html, poweredBy) {
  const found = [];

  // X-Powered-By is the server stating its own stack, so it carries more weight than
// anything inferred from markup.
  if (poweredBy) {
    const known = { express: 'Express', php: 'PHP', 'asp.net': 'ASP.NET', 'php/': 'PHP' };
    for (const [needle, name] of Object.entries(known)) {
      if (poweredBy.toLowerCase().includes(needle)) {
        found.push({ name, confidence: 'high', evidence: `X-Powered-By: ${poweredBy}` });
      }
    }
  }

  for (const fw of FRAMEWORK_MARKERS) {
    const hit = fw.patterns.find((p) => html.includes(p));
    if (hit) found.push({ name: fw.name, confidence: fw.confidence, evidence: `HTML marker "${hit}"` });
  }

  const seen = new Set();
  return found.filter((f) => !seen.has(f.name) && seen.add(f.name));
}

// Cap the read so a target cannot stream an unbounded body into the adapter.
export async function fingerprint(url, safeFetch, probeTls = safeTlsInfo) {
  const findings = [];
  const limitations = [];

  const fetched = await safeFetch(url);
  if (!fetched.ok) {
    limitations.push(`http fetch failed: ${fetched.reason}`);
    return { findings, cdn: null, tls: null, limitations };
  }

  const { response, finalUrl } = fetched;
  const headers = response.headers;
  const serverHeader = headers.get('server');
  const poweredBy = headers.get('x-powered-by');

  if (!response.ok) {
    // Headers still describe the real server, but anything read from the body
    // came off an error page — say so rather than letting it read as a normal scan.
    limitations.push(`target returned HTTP ${response.status} — response headers are real, but any framework marker was read from the error page`);
  }

  if (serverHeader) {
    findings.push(finding('server', serverHeader, 'observation',
      `Server response header: "${serverHeader}"`, 'high'));
  }

  if (poweredBy) {
    findings.push(finding('powered_by', poweredBy, 'observation',
      `X-Powered-By response header: "${poweredBy}"`, 'high'));
  }

  let html = '';
  try {
    const body = await readCapped(response, MAX_HTML_BYTES);
    html = body.text;
    if (body.truncated) {
      // The marker scan below only saw the first chunk of the document, so a
      // framework placed further down was never in scope.
      limitations.push(`response body truncated at ${MAX_HTML_BYTES} bytes; framework markers below that point were not checked`);
    }
  } catch (err) {
    limitations.push(`could not read response body: ${err.message}`);
  }

  const frameworks = detectFramework(html, poweredBy);
  if (frameworks.length) {
    for (const fw of frameworks) {
      findings.push(finding('framework', fw.name, 'derivation',
        `${fw.evidence} — inferred from markup, not declared by the server`, fw.confidence));
    }
  } else {
    limitations.push('no framework markers found in the first 512KB of markup');
  }

  const cdn = detectCdn(headers, serverHeader);
  if (cdn) {
    findings.push(finding('cdn', cdn.name, 'observation', cdn.evidence, 'high'));
  }

  let tls = null;
  let target;
  try {
    target = new URL(finalUrl);
  } catch {
    target = null;
  }

  if (target && target.protocol === 'https:') {
    const port = target.port ? Number(target.port) : 443;
    const info = await probeTls(target.hostname, port);
    if (info.ok) {
      tls = info.tls;
      if (tls.issuer) {
        findings.push(finding('tls_issuer', tls.issuer, 'observation',
          `TLS certificate issuer: ${tls.issuer}`, 'high'));
      }
      if (tls.expiry) {
        findings.push(finding('tls_expiry', tls.expiry, 'observation',
          `TLS certificate valid_to: ${tls.expiry}`, 'high'));
      }
    } else {
      limitations.push(`tls probe failed: ${info.reason}`);
    }
  } else {
    limitations.push('target is not https, no certificate to inspect');
  }

  return { findings, cdn: cdn?.name ?? null, tls, limitations };
}