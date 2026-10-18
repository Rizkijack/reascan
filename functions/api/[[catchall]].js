// /api/<anything that is not analyze|health> — JSON 404.
//
// Pages falls back to static assets when no function matches, so without this
// a typo'd API path answered 200 text/html (the page's own index): a client
// parsing every /api/* reply as JSON chokes on it, and the local dev server
// answered the same path with 404 JSON — a contract bug that would only ever
// be visible in production.
//
// Precedence is safe here: Cloudflare routes the request to the file with the
// fewest wildcards, so api/analyze.js and api/health.js keep their exact paths
// and this only receives what no other function claimed.

export function onRequest() {
  return new Response(JSON.stringify({ status: 'error', error: 'no such route' }), {
    status: 404,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}
