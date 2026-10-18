// POST /api/analyze — SSRF guard layer 1 + pure proxy to the VM adapter.
//
// This function validates and forwards. It never analyzes: the 10ms Workers CPU
// budget is what keeps this project on the free tier, and every byte of compute
// belongs on the VM (PLAN.md §2 golden rule).
//
// Layer division of labour:
//   here  — scheme + DNS-resolved-IP denylist on the URL the USER supplied
//   VM    — same denylist re-checked, plus redirect-hop validation (safeFetch),
//           because that is where the actual fetches to the target happen.
// The edge never fetches the target, so hop-walking here would be dead code;
// a hostile redirect is stopped at the adapter, where it is followed.
//
// The denylist lives in TWO places — this file and vm-adapter/lib/urlGuard.js.
// Changing one means changing the other (AGENTS.md security invariants).

import { resolve4, resolve6 } from 'node:dns/promises';

export const DENYLIST_CIDRS = [
  '127.0.0.0/8', // loopback
  '10.0.0.0/8', // private
  '172.16.0.0/12', // private
  '192.168.0.0/16', // private
  '169.254.0.0/16', // link-local + cloud metadata
  '0.0.0.0/8', // this network
  '::1/128', // loopback
  'fc00::/7', // unique local
];

// Octets must be canonical decimal — no leading zeros. node:net rejects
// '010.0.0.1' outright and this mirrors it so the two guards answer identically
// on the non-canonical forms their exports can be handed. Neither guard ever
// sees one through validateUrl: WHATWG canonicalises the host first, and it reads
// 010 as octal anyway.
function parseIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^(0|[1-9]\d{0,2})$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    bytes[i] = n;
  }
  return bytes;
}

function parseIPv6(ip) {
  let addr = ip;
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);

  // Normalise a trailing dotted-quad (::ffff:127.0.0.1) into two hex groups.
  const lastColon = addr.lastIndexOf(':');
  const tail = addr.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail);
    if (!v4) return null;
    const [a, b, c, d] = Array.from(v4, (x) => x.toString(16).padStart(2, '0'));
    addr = `${addr.slice(0, lastColon + 1)}${a}${b}:${c}${d}`;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tailGroups = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tailGroups.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...tailGroups];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    const value = Number.parseInt(groups[i], 16);
    bytes[i * 2] = value >> 8;
    bytes[i * 2 + 1] = value & 0xff;
  }
  return bytes;
}

function ipInCidr(bytes, cidr) {
  const [net, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const netBytes = bytes.length === 4 ? parseIPv4(net) : parseIPv6(net);
  if (!netBytes || netBytes.length !== bytes.length) return false;
  if (!Number.isInteger(bits) || bits < 0 || bits > bytes.length * 8) return false;

  const wholeBytes = bits >> 3;
  const remainder = bits & 7;
  for (let i = 0; i < wholeBytes; i++) {
    if (bytes[i] !== netBytes[i]) return false;
  }
  if (remainder) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((bytes[wholeBytes] & mask) !== (netBytes[wholeBytes] & mask)) return false;
  }
  return true;
}

// ::ffff:a.b.c.d and the deprecated ::a.b.c.d route to the IPv4 address on OS
// stacks; without unmapping, http://[::ffff:127.0.0.1]/ would pass an
// IPv6-only denylist. Same rule as the adapter's urlGuard.
function mappedIPv4(bytes) {
  for (let i = 0; i < 10; i++) {
    if (bytes[i] !== 0) return null;
  }
  const isV4Mapped = bytes[10] === 0xff && bytes[11] === 0xff;
  const isV4Compat = bytes[10] === 0 && bytes[11] === 0;
  if (!isV4Mapped && !isV4Compat) return null;
  return parseIPv4(`${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`);
}

export function isDeniedIp(ip) {
  const trimmed = typeof ip === 'string' ? ip.trim() : '';
  const v4 = parseIPv4(trimmed);
  const v6 = v4 ? null : parseIPv6(trimmed);
  const bytes = v4 ?? v6;
  if (!bytes) return false;

  const candidates = [bytes];
  if (v6) {
    const mapped = mappedIPv4(v6);
    if (mapped) candidates.push(mapped);
  }

  return candidates.some((c) => DENYLIST_CIDRS.some((cidr) => ipInCidr(c, cidr)));
}

const defaultDns = {
  // Workers' node:dns implements resolve4/resolve6 but NOT lookup — lookup
  // throws "Not implemented" at the edge, so resolve* is the only path here.
  async all(hostname) {
    const [a, aaaa] = await Promise.allSettled([
      resolve4(hostname, { all: true }),
      resolve6(hostname, { all: true }),
    ]);
    const records = [
      ...(a.status === 'fulfilled' ? a.value : []),
      ...(aaaa.status === 'fulfilled' ? aaaa.value : []),
    ];
    const addresses = normalizeAddresses(records);
    if (addresses.length === 0) {
      // Surface why: the aggregate error is more useful than an empty list.
      const err = a.status === 'rejected' ? a.reason : aaaa.reason;
      throw err ?? new Error(`dns returned no address: ${hostname}`);
    }
    return addresses;
  },
};

// resolve4/resolve6 yield bare address strings, while lookup-style resolvers
// yield {address, family} objects. Mapping r.address blindly turns the former
// into [undefined], which isDeniedIp() accepts — the guard would let every
// hostname through. Both shapes are normalised here, and tested, because the
// real resolver shape is exactly what a fake DNS seam cannot prove.
export function normalizeAddresses(records) {
  const out = [];
  for (const record of records) {
    const address = typeof record === 'string' ? record : record?.address;
    if (typeof address === 'string' && address) out.push(address);
  }
  return out;
}

// Dependency-injection seam: tests pass a fake resolver instead of hitting DNS
// (AGENTS.md testing). Module-level code reads no env — this file must import
// cleanly under `node --test`.
export async function validateUrl(rawUrl, dns = defaultDns) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'invalid url' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: `blocked scheme: ${url.protocol}` };
  }

  // URL keeps IPv6 literals bracketed ("[::1]").
  const host = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;

  // IP literals are checked directly — no DNS round-trip to confirm that
  // 127.0.0.1 is 127.0.0.1.
  if (parseIPv4(host) || (host.includes(':') && parseIPv6(host))) {
    if (isDeniedIp(host)) {
      return { ok: false, reason: `url blocked: ${host} is a private IP` };
    }
    return { ok: true, url };
  }

  let addresses;
  try {
    addresses = await dns.all(host);
  } catch (err) {
    return { ok: false, reason: `dns resolution failed: ${host} (${err?.message ?? 'no address'})` };
  }

  for (const address of addresses) {
    if (isDeniedIp(address)) {
      return { ok: false, reason: `url blocked: resolves to private IP ${address}` };
    }
  }

  return { ok: true, url };
}

function json(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// Any method but POST used to fall through to the static layer and answer
// 200 text/html (the page's own index) — a client parsing every /api/* reply
// as JSON would choke on it. This does not touch the POST contract, which
// stays 200 / 422 / 502 (DESIGN §5).
export function onRequestGet() {
  return json(405, { status: 'error', error: 'method not allowed' });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json(422, { status: 'error', error: 'body is not valid JSON' });
  }

  const check = await validateUrl(payload?.url);
  if (!check.ok) return json(422, { status: 'error', error: check.reason });

  if (!env.VM_ADAPTER_URL || !env.API_KEY) {
    return json(500, { status: 'error', error: 'analysis engine is not configured' });
  }

  // The adapter's own deadline is 70s; 75s here catches a dead tunnel rather
  // than leaving the browser hanging until Workers kills the request.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 75000);

  let engine;
  try {
    engine = await fetch(new URL('/analyze', env.VM_ADAPTER_URL), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.API_KEY,
      },
      body: JSON.stringify({
        url: check.url.toString(),
        categories: Array.isArray(payload.categories) ? payload.categories : undefined,
      }),
      signal: controller.signal,
    });
  } catch {
    return json(502, { status: 'error', error: 'analysis engine unreachable' });
  } finally {
    clearTimeout(timer);
  }

  let result;
  try {
    result = await engine.json();
  } catch {
    return json(502, { status: 'error', error: 'analysis engine unreachable' });
  }

  // Public contract (DESIGN §5) defines exactly three statuses for this route:
  // 200, 422, 502. The engine's own code is therefore NOT echoed back — a 401
  // (adapter key mismatch) would advertise an auth prompt to the browser, and a
  // 504 (deadline) is an engine-internal condition. A 422 keeps its meaning
  // ("blocked"), anything else is "the engine did not give you findings" — a
  // 502 — with the engine's reason preserved verbatim in the body.
  if (!engine.ok) {
    const status = engine.status === 422 ? 422 : 502;
    return json(status, {
      status: 'error',
      error: result?.error ?? `analysis engine failed (${engine.status})`,
    });
  }

  // A 2xx that is not {status:'ok'} is a contract breach, not a success. Echoing
  // it back as 200 would put {status:'error'} under a success code and break
  // "200 means done" for every client; result may also be null or a non-object
  // (adapter returned `null`), which must land as JSON here rather than as a
  // TypeError turning into a 500 HTML page.
  if (result?.status !== 'ok' || typeof result.findings !== 'object' || result.findings === null) {
    return json(502, { status: 'error', error: 'analysis engine returned an unexpected response' });
  }

  return json(200, { status: 'done', findings: result.findings });
}
