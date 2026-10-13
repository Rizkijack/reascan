// SSRF guard — security core. Every outbound fetch in the adapter goes through
// safeFetch(). Never call global fetch() directly.
//
// Why the redirect handling matters: Node's fetch follows redirects on its own,
// so a hostile target can answer 302 and land the adapter inside 169.254.169.254
// (cloud instance metadata) or RFC1918 space. Every hop is therefore resolved and
// denylist-checked before it is followed.

import { isIPv4, isIPv6 } from 'node:net';
import { lookup } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';

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

const UA = 'reascan/0.1 (+https://github.com/Rizkijack/reascan)';

function ipv6ToBytes(ip) {
  let addr = ip;
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);

  // Normalise a trailing dotted-quad (::ffff:127.0.0.1) into two hex groups.
  // Each IPv6 group is 16 bits, so four octets become two 4-digit groups —
  // '7f:00' would parse as 0x007f, not 0x7f00.
  const lastColon = addr.lastIndexOf(':');
  const tail = addr.slice(lastColon + 1);
  if (isIPv4(tail)) {
    const v4 = parseIp(tail);
    if (!v4) return null;
    const [a, b, c, d] = Array.from(v4.bytes, (x) => x.toString(16).padStart(2, '0'));
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
    const value = Number.parseInt(groups[i], 16);
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null;
    bytes[i * 2] = value >> 8;
    bytes[i * 2 + 1] = value & 0xff;
  }
  return bytes;
}

function parseIp(ip) {
  if (typeof ip !== 'string') return null;
  const trimmed = ip.trim();
  if (isIPv4(trimmed)) {
    const parts = trimmed.split('.');
    const bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) bytes[i] = Number(parts[i]);
    return { version: 4, bytes };
  }
  if (isIPv6(trimmed)) {
    const bytes = ipv6ToBytes(trimmed);
    return bytes ? { version: 6, bytes } : null;
  }
  return null;
}

// Pure — no network, no DNS. Exported so the guard is testable offline.
export function ipInCidr(ip, cidr) {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) return false;
  const addr = parseIp(ip);
  const net = parseIp(cidr.slice(0, slash));
  const bits = Number(cidr.slice(slash + 1));
  if (!addr || !net || addr.version !== net.version) return false;

  const maxBits = addr.version === 4 ? 32 : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) return false;

  const wholeBytes = bits >> 3;
  const remainder = bits & 7;
  for (let i = 0; i < wholeBytes; i++) {
    if (addr.bytes[i] !== net.bytes[i]) return false;
  }
  if (remainder) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((addr.bytes[wholeBytes] & mask) !== (net.bytes[wholeBytes] & mask)) return false;
  }
  return true;
}

// ::ffff:a.b.c.d and the deprecated ::a.b.c.d are IPv4 addresses wearing an IPv6
// hat. Matching only against the IPv6 ranges would let a target smuggle 127.0.0.1
// or 169.254.169.254 through as an "IPv6" literal — OS stacks still route both
// forms to the IPv4 address.
function mappedIPv4(bytes) {
  for (let i = 0; i < 10; i++) {
    if (bytes[i] !== 0) return null;
  }
  const isV4Mapped = bytes[10] === 0xff && bytes[11] === 0xff;
  const isV4Compat = bytes[10] === 0 && bytes[11] === 0;
  if (!isV4Mapped && !isV4Compat) return null;
  return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
}

export function isDeniedIp(ip) {
  const parsed = parseIp(ip);
  if (!parsed) return false;

  const candidates = [ip.trim()];
  if (parsed.version === 6) {
    const mapped = mappedIPv4(parsed.bytes);
    if (mapped) candidates.push(mapped);
  }

  return DENYLIST_CIDRS.some((cidr) => candidates.some((c) => ipInCidr(c, cidr)));
}

// Residual risk: this resolves DNS and checks the answers, but fetch() resolves
// again when it opens the socket. A host answering with a public address here and
// a private one a moment later wins the race. PLAN.md 7 specifies resolve-then-check
// as the design; closing the window fully needs IP pinning (connect to the checked
// IP, set Host and SNI by hostname), which changes the validateUrl contract in
// DESIGN.md 3.6. Noted here so nobody mistakes this for a complete fix.
export async function validateUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'invalid url' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: `blocked scheme: ${url.protocol}` };
  }

  // URL keeps IPv6 literals bracketed ("[::1]"); dns.lookup wants them bare.
  const host = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;

  const resolved = await resolvePublic(host);
  if (!resolved.ok) return resolved;

  return { ok: true, url };
}

// Resolve and refuse the host unless every answer is public. Shared by the HTTP
// path and the TLS path so both legs apply identical rules.
export async function resolvePublic(hostname) {
  let addresses;
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    return { ok: false, reason: `dns resolution failed: ${hostname}` };
  }

  if (addresses.length === 0) {
    return { ok: false, reason: `dns returned no address: ${hostname}` };
  }

  // One private answer among several is enough to refuse the whole host.
  for (const { address } of addresses) {
    if (isDeniedIp(address)) {
      return { ok: false, reason: `url blocked: resolves to private IP ${address}` };
    }
  }

  return { ok: true, addresses };
}

// A raw TLS socket is outbound traffic too, so it goes through here rather than
// being opened by the caller. Connecting to the already-checked address (not the
// hostname) also closes the rebinding race for this leg: the address we validated
// is the address we dial.
//
// rejectUnauthorized is off on purpose — this reads the presented certificate for
// reporting and is not authenticating anything.
export async function safeTlsInfo(hostname, port = 443, { timeoutMs = 10000 } = {}) {
  const publicHost = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
  const resolved = await resolvePublic(publicHost);
  if (!resolved.ok) return resolved;

  const address = resolved.addresses[0].address;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      resolve(value);
    };

    let socket;
    try {
      socket = tlsConnect({
        host: address,
        port,
        servername: publicHost,
        rejectUnauthorized: false,
      });
    } catch (err) {
      resolve({ ok: false, reason: `tls connect failed: ${err.message}` });
      return;
    }

    const timer = setTimeout(() => finish({ ok: false, reason: `tls timeout after ${timeoutMs}ms` }), timeoutMs);

    socket.once('error', (err) => finish({ ok: false, reason: `tls error: ${err.message}` }));
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate(false) || {};
      finish({
        ok: true,
        tls: {
          issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
          subject: cert.subject?.CN ?? null,
          expiry: cert.valid_to ?? null,
          validFrom: cert.valid_from ?? null,
          protocol: socket.getProtocol?.() ?? null,
        },
      });
    });
  });
}

export async function safeFetch(rawUrl, { timeoutMs = 10000, maxRedirects = 3 } = {}) {
  let target = rawUrl;
  let hops = 0;

  for (;;) {
    const check = await validateUrl(target);
    if (!check.ok) return check;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetch(check.url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': UA, accept: '*/*' },
      });
    } catch (err) {
      return {
        ok: false,
        reason: controller.signal.aborted ? `timeout after ${timeoutMs}ms` : `fetch failed: ${err.message}`,
      };
    } finally {
      clearTimeout(timer);
    }

    const location = response.headers.get('location');
    if (response.status >= 300 && response.status < 400 && location) {
      if (hops >= maxRedirects) {
        return { ok: false, reason: `too many redirects (max ${maxRedirects})` };
      }
      hops++;
      try {
        target = new URL(location, check.url).toString();
      } catch {
        return { ok: false, reason: `invalid redirect location: ${location}` };
      }
      continue;
    }

    return { ok: true, response, finalUrl: check.url.toString() };
  }
}