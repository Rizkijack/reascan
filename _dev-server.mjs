// Local dev server — serves frontend/ and routes /api/* to the real Pages
// Functions, so the frontend on this machine talks to the real adapter.
//
//   node _dev-server.mjs        ->  http://127.0.0.1:8788
//
// The functions get their env from .dev.vars at the repo root — the same file
// `wrangler pages dev` reads — so there is exactly one place holding the adapter
// URL and the API key. Change one file, not two.
//
// Not a production path and not a wrangler replacement. It reproduces the Pages
// routing convention (/functions/api/analyze.js -> /api/analyze) and nothing
// else: no build step, no preview deploys, no secret store.
//
// Leading underscore = local tooling, not part of the shipped site — wrangler
// only ever publishes frontend/, so this file never reaches production.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';

const ROOT = resolve(new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const STATIC = join(ROOT, 'frontend');
const PORT = Number(process.env.DEV_PORT) || 8788;
const HOST = '127.0.0.1';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

// Pages Functions read config from env, never from a module-level read, so
// this file owns the only place those values are supplied locally.
async function loadDevVars() {
  let raw;
  try {
    raw = await readFile(join(ROOT, '.dev.vars'), 'utf8');
  } catch {
    throw new Error('.dev.vars missing at the repo root — /api needs VM_ADAPTER_URL and API_KEY');
  }
  const env = {};
  for (const line of raw.split('\n')) {
    const m = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (m) env[m[1]] = m[2].trim();
  }
  return env;
}

// Method matters: Pages answers a wrong method on a known path with 405 JSON
// and an unknown /api path with 404 JSON (functions/api/[[catchall]].js). The
// dev server must say the same things, or a contract bug shows up only in
// production.
const HANDLERS = {
  '/api/analyze': {
    GET: () => import('./functions/api/analyze.js').then((m) => m.onRequestGet),
    POST: () => import('./functions/api/analyze.js').then((m) => m.onRequestPost),
  },
  '/api/health': {
    GET: () => import('./functions/api/health.js').then((m) => m.onRequestGet),
    POST: () => import('./functions/api/health.js').then((m) => m.onRequestPost),
  },
};

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

async function pipe(res, response) {
  const headers = {};
  for (const [k, v] of response.headers) headers[k] = v;
  res.writeHead(response.status, headers);
  res.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined);
}

const server = createServer(async (req, res) => {
  const path = new URL(req.url, `http://${HOST}:${PORT}`).pathname;

  // Path traversal guard: the resolved file must stay inside frontend/.
  if (path.startsWith('/api/')) {
    const load = HANDLERS[path]?.[req.method];
    if (!load) {
      const knownPath = Boolean(HANDLERS[path]);
      res.writeHead(knownPath ? 405 : 404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'error', error: knownPath ? 'method not allowed' : 'no such route' }));
      return;
    }
    try {
      const handler = await load();
      const request = new Request(`http://${HOST}:${PORT}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body: await readBody(req),
      });
      await pipe(res, await handler({ request, env: await loadDevVars(), params: {} }));
    } catch (err) {
      // Never echo the engine's internals; a dev-server crash is ours, not the
      // target's, so it goes to stderr and the client gets a flat 500.
      process.stderr.write(`dev-server ${path}: ${err.stack || err.message}\n`);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'error', error: 'dev server failure' }));
    }
    return;
  }

  const rel = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
  const file = resolve(join(STATIC, rel));
  if (file !== STATIC && !file.startsWith(STATIC + sep)) {
    res.writeHead(403).end('forbidden');
    return;
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, {
      'content-type': MIME[extname(file).toLowerCase()] ?? 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
});

loadDevVars()
  .then((env) => {
    server.listen(PORT, HOST, () => {
      process.stderr.write(
        `reascan dev server on http://${HOST}:${PORT}\n`
        + `  adapter: ${env.VM_ADAPTER_URL ?? '(VM_ADAPTER_URL not set — /api/analyze will 500)'}\n`
        + `  api key: ${env.API_KEY ? `set (${env.API_KEY.length} chars)` : '(API_KEY not set — /api/analyze will 500)'}\n`,
      );
    });
  })
  .catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
