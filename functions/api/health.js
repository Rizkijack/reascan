// GET /api/health — liveness answer for the static layer itself.
//
// Deliberately does NOT probe the VM adapter: this endpoint has no credentials
// to forward and a health check that silently triggers a tunnel round-trip
// turns every monitoring ping into an engine wake-up. The deep check lives on
// the VM (curl <tunnel>/health with X-API-Key — docs/vm-setup.md §6).

export async function onRequestGet() {
  return new Response(JSON.stringify({ status: 'ok' }), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// GET only. Any other method would fall through to the static layer and answer
// 200 text/html instead of JSON — same rule as functions/api/[[catchall]].js.
export function onRequestPost() {
  return new Response(JSON.stringify({ status: 'error', error: 'method not allowed' }), {
    status: 405,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}
