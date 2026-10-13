// reascan frontend — vanilla JS, zero framework.
//
// State machine: one `state` object + render(). The API is sync (seconds), so
// there is no polling and no job state — phase 2 async adds an interval here,
// not a rewrite.
//
// Every string rendered from a findings object is TARGET-CONTROLLED (headers,
// marker values, endpoint paths — all attacker-influenced on a hostile site).
// That is why this file builds DOM with createElement/textContent only: one
// innerHTML with a finding value would turn the report into an XSS sink.

const HISTORY_KEY = 'reascan:history';
const HISTORY_MAX = 50;

const state = { phase: 'idle', findings: null, error: null };

const $ = (id) => document.getElementById(id);

// --- history (localStorage, per-browser, no backend) ------------------------

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // A corrupt entry must not break the page — the history is a convenience,
    // not the report.
    return [];
  }
}

// Set when a report could not be stored, so renderHistory can say so instead of
// the list quietly failing to grow.
let historyNotice = '';

function saveToHistory(findings) {
  const history = loadHistory();
  history.unshift({
    url: findings.url,
    timestamp: findings.timestamp,
    confidence: findings.verdict?.confidence ?? 'unknown',
    findings,
  });
  if (history.length > HISTORY_MAX) history.length = HISTORY_MAX;

  // localStorage is about 5MB and a heavy report is tens of KB (endpoints and
  // per-bundle detail dominate), so the quota is genuinely reachable at 50
  // entries. onQuotaExceededError is not available everywhere, so this is driven
  // by the throw rather than a precomputed size.
  //
  // A failed setItem leaves the previous value untouched, which is what makes
  // trimming safe here: the worst case is an older, smaller history still intact.
  historyNotice = '';
  let candidate = history;
  for (;;) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(candidate));
      if (candidate.length < history.length) {
        historyNotice = `kept the newest ${candidate.length} analyses — the rest no longer fit in this browser's storage`;
      }
      break;
    } catch {
      if (candidate.length <= 1) {
        historyNotice = 'this report is too large to keep in this browser, so history was left as it was';
        break;
      }
      candidate = candidate.slice(0, Math.max(1, Math.floor(candidate.length / 2)));
    }
  }

  renderHistory();
}

function renderHistory() {
  const section = $('history-section');
  const list = $('history-list');
  const history = loadHistory();

  list.textContent = '';
  section.hidden = history.length === 0 && !historyNotice;

  if (historyNotice) {
    list.append(el('li', 'history-notice', historyNotice));
  }

  for (const entry of history) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';

    const url = document.createElement('span');
    url.className = 'url';
    url.textContent = entry.url ?? '(unknown url)';

    const meta = document.createElement('span');
    meta.className = 'meta';
    const when = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '';
    meta.textContent = `${entry.confidence ?? '?'} · ${when}`;

    btn.append(url, meta);
    btn.addEventListener('click', () => {
      state.phase = 'done';
      state.findings = entry.findings;
      state.error = null;
      render();
      $('results').scrollIntoView({ behavior: 'smooth' });
    });

    li.append(btn);
    list.append(li);
  }
}

// --- rendering --------------------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderVerdict(verdict) {
  const box = el('div', 'verdict');
  if (!verdict) return box;

  const badge = el('span', `badge ${verdict.confidence ?? 'low'}`, verdict.confidence ?? 'unknown');
  box.append(badge);

  const limitations = verdict.limitations ?? [];
  const unknowns = verdict.unknowns ?? [];

  if (limitations.length) {
    const div = el('div', 'limitations');
    div.append(el('h3', null, `Limitations (${limitations.length})`));
    const ul = document.createElement('ul');
    for (const item of limitations) ul.append(el('li', null, String(item)));
    div.append(ul);
    box.append(div);
  }

  if (unknowns.length) {
    const div = el('div', 'unknowns');
    div.append(el('h3', null, `Unknowns (${unknowns.length})`));
    const ul = document.createElement('ul');
    for (const item of unknowns) ul.append(el('li', null, String(item)));
    div.append(ul);
    box.append(div);
  }

  return box;
}

function renderFingerprint(fp) {
  const wrap = document.createDocumentFragment();
  if (!fp?.findings?.length && !fp?.tls) return wrap;

  wrap.append(el('h3', null, 'Fingerprint'));

  if (fp.findings?.length) {
    const table = document.createElement('table');
    const head = document.createElement('tr');
    for (const label of ['Key', 'Value', 'Type', 'Evidence', 'Confidence']) {
      head.append(el('th', null, label));
    }
    table.append(head);

    for (const f of fp.findings) {
      const row = document.createElement('tr');
      row.append(
        el('td', null, String(f.key)),
        el('td', null, Array.isArray(f.value) ? f.value.join(', ') : String(f.value)),
        el('td', null, String(f.type)),
        el('td', null, String(f.evidence)),
        el('td', null, String(f.confidence)),
      );
      table.append(row);
    }
    wrap.append(table);
  }

  if (fp.tls) {
    const meta = el('div', 'meta');
    const parts = [
      fp.tls.issuer && `issuer ${fp.tls.issuer}`,
      fp.tls.subject && `subject ${fp.tls.subject}`,
      fp.tls.expiry && `expires ${fp.tls.expiry}`,
      fp.tls.protocol && fp.tls.protocol,
    ].filter(Boolean);
    if (parts.length) {
      meta.append(el('span', null, `TLS: ${parts.join(' · ')}`));
      wrap.append(meta);
    }
  }

  return wrap;
}

function renderBundles(bundles) {
  const wrap = document.createDocumentFragment();
  if (!bundles?.length) return wrap;

  wrap.append(el('h3', null, `JS bundles (${bundles.length})`));

  for (const b of bundles) {
    const card = el('div', 'bundle');
    card.append(el('div', 'src', String(b.src)));

    const flags = [
      `${b.size_kb ?? '?'} KB`,
      b.sourcemap ? 'sourcemap' : null,
      b.obfuscated ? 'obfuscated' : null,
    ].filter(Boolean);
    card.append(el('div', 'meta', flags.join(' · ')));

    if (b.endpoints?.length) {
      const eps = el('div', 'endpoints');
      for (const ep of b.endpoints) eps.append(el('code', null, String(ep)));
      card.append(eps);
    }

    wrap.append(card);
  }

  return wrap;
}

function renderFindings(findings) {
  const body = $('findings-body');
  body.textContent = '';
  $('verdict').textContent = '';
  $('verdict').append(renderVerdict(findings.verdict));

  body.append(renderFingerprint(findings.fingerprint));
  body.append(renderBundles(findings.js_bundles));
}

function render() {
  const status = $('status');
  const results = $('results');
  const btn = $('analyze-btn');

  status.hidden = state.phase === 'idle' || state.phase === 'done';
  btn.disabled = state.phase === 'loading';

  if (state.phase === 'loading') {
    status.className = 'status';
    status.textContent = '';
    status.append(el('span', 'spinner'), document.createTextNode('Analyzing… fetching headers and bundles, up to ~45s.'));
    results.hidden = true;
  } else if (state.phase === 'error') {
    status.className = 'status error';
    status.textContent = state.error;
    results.hidden = true;
  } else if (state.phase === 'done' && state.findings) {
    status.className = 'status';
    results.hidden = false;
    renderFindings(state.findings);
  }
}

// --- submit -----------------------------------------------------------------

async function handleSubmit(e) {
  e.preventDefault();

  const input = $('target-url');
  let url;
  try {
    url = new URL(input.value.trim());
  } catch {
    state.phase = 'error';
    state.error = 'Enter a valid URL, including http:// or https://';
    render();
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    state.phase = 'error';
    state.error = 'Only http:// and https:// targets are supported';
    render();
    return;
  }

  const categories = [...document.querySelectorAll('input[name="category"]:checked')]
    .map((c) => c.value);
  if (!categories.length) {
    state.phase = 'error';
    state.error = 'Pick at least one category';
    render();
    return;
  }

  state.phase = 'loading';
  render();

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: url.toString(), categories }),
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`unexpected response from the analyzer (${res.status})`);
    }

    if (data.status !== 'done') {
      state.phase = 'error';
      state.error = data.error ?? `analysis failed (${res.status})`;
    } else if (!data.findings || typeof data.findings !== 'object') {
      // {status:'done'} with no findings is a contract breach, not a transport
      // problem. Letting it reach saveToHistory() threw on findings.url and
      // surfaced as "could not reach the analyzer", blaming the network for a
      // server that answered wrongly.
      state.phase = 'error';
      state.error = 'the analyzer returned a completed result with no findings';
    } else {
      state.phase = 'done';
      state.findings = data.findings;
      saveToHistory(data.findings);
    }
  } catch (err) {
    state.phase = 'error';
    state.error = `could not reach the analyzer: ${err.message}`;
  }

  render();
}

// --- boot -------------------------------------------------------------------

$('analyze-form').addEventListener('submit', handleSubmit);

$('clear-history').addEventListener('click', () => {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch {
    // storage disabled — list simply re-renders from the same empty source
  }
  historyNotice = '';
  renderHistory();
});

renderHistory();
render();
