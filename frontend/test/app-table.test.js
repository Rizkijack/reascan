import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, createDocument, fire, storageBean } from './dom-shim.js';

// app.js fingerprint table contract, driven ONLY through the real render path:
// seed history -> click the history row -> render() -> the report table exists.
// Pinned: header-click sorting (single glyph, rank for categorical columns,
// numeric collation on Value), search filtering with the "n / N" summary, and
// renderCharts() skipping the donut when the confidence data is all zeros.

const storage = storageBean();

const FINDINGS1 = {
  url: 'https://a.example/',
  timestamp: '2026-01-01T00:00:00Z',
  verdict: { confidence: 'high', limitations: [], unknowns: [] },
  fingerprint: {
    findings: [
      { key: 'f.alpha', value: 10, type: 'derivation', evidence: 'Everything proof alpha', confidence: 'medium' },
      { key: 'c.note', value: 9, type: 'observation', evidence: 'Signed note', confidence: 'high' },
      { key: 'k.zed', value: 'abc', type: 'inference', evidence: 'Pattern inference', confidence: 'low' },
    ],
  },
};

// All confidences outside high/medium/low -> donut total = 0 -> skipped.
const FINDINGS2 = {
  url: 'https://b.example/',
  timestamp: '2026-02-01T00:00:00Z',
  verdict: { confidence: 'observed', limitations: [], unknowns: [] },
  fingerprint: {
    findings: [
      { key: 'a.one', value: 1, type: 'observation', evidence: 'Header seen', confidence: 'observed' },
      { key: 'b.two', value: 2, type: 'observation', evidence: 'Route seen', confidence: 'observed' },
    ],
  },
};

// Globals + seeded history must exist BEFORE ../app.js boots: its bottom-level
// renderHistory() reads localStorage and wires the buttons.
storage.setItem('reascan:history', JSON.stringify([
  { url: FINDINGS1.url, timestamp: FINDINGS1.timestamp, confidence: 'high', findings: FINDINGS1 },
  { url: FINDINGS2.url, timestamp: FINDINGS2.timestamp, confidence: 'observed', findings: FINDINGS2 },
]));

const ids = {
  'analyze-form': new El('form'),
  'target-url': new El('input'),
  'analyze-btn': new El('button'),
  'status': new El('p'),
  'results': new El('section'),
  'verdict': new El('div'),
  'findings-body': new El('div'),
  'history-section': new El('section'),
  'history-list': new El('div'),
  'clear-history': new El('button'),
  'charts': new El('div'),
};
globalThis.document = createDocument({ ids });
globalThis.localStorage = storage;

await import('../app.js'); // boot side effect: renderHistory() + render() + history buttons wired

let tools, table, tbody, thead, count, search, historyButtons;

function openReport(theFindings) {
  historyButtons ??= ids['history-list'].all.filter((n) => n.classList.contains('history-open'));
  const idx = theFindings === FINDINGS1 ? 0 : 1;
  fire(historyButtons[idx], 'click'); // -> state.findings set -> render() -> table
  const body = ids['findings-body'];
  tools = body.all.find((n) => n.classList.contains('table-tools'));
  table = body.all.find((n) => n.tagName === 'table');
  thead = table.children.find((c) => c.tagName === 'thead');
  tbody = table.children.find((c) => c.tagName === 'tbody');
  count = tools.children[1];
  search = tools.children[0];
}

const rowValues = (tb) => tb.children.map((tr) => tr.children.map((td) => td.textContent));

test('rendering a report produces the sortable/searchable table (exists, 3 rows, 3 / 3)', () => {
  openReport(FINDINGS1);
  assert.ok(table, 'the report table must render');
  assert.equal(tbody.children.length, 3);
  assert.equal(count.textContent, '3 / 3');
  assert.equal(search.tagName, 'input');
  assert.equal(search.type, 'search');
  assert.equal(search.autocomplete, 'off');
  // donut side of renderCharts: high/medium/low all present -> donut-box exists
  const charts = ids['charts'];
  assert.equal(charts.hidden, false);
  assert.ok(charts.all.some((n) => n.classList.contains('donut-box')), 'non-zero confidence data must draw the donut');
});

test('sorting by Value uses numeric collation (9 < 10 < abc), glyph pinned to it alone', () => {
  const ths = thead.children[0].children;
  const glyphOf = (th) => th.children[0].textContent;
  fire(ths[1], 'click'); // Value asc
  assert.deepEqual(rowValues(tbody).map((r) => r[1]), ['9', '10', 'abc']);
  assert.equal(glyphOf(ths[1]), '▲');
  assert.equal(glyphOf(ths[0]), '');
  fire(ths[1], 'click'); // Value desc (toggle)
  assert.deepEqual(rowValues(tbody).map((r) => r[1]), ['abc', '10', '9']);
  assert.equal(glyphOf(ths[1]), '▼');
});

test('Confidence sorts by rank (high, medium, low), not lexically', () => {
  const ths = thead.children[0].children;
  fire(ths[4], 'click');
  assert.deepEqual(rowValues(tbody).map((r) => r[4]), ['high', 'medium', 'low']);
  // switching columns clears the old glyph: two live glyphs would be ambiguous
  assert.equal(ths[1].children[0].textContent, '');
  assert.equal(ths[4].children[0].textContent, '▲');
  fire(ths[4], 'click');
  assert.deepEqual(rowValues(tbody).map((r) => r[4]), ['low', 'medium', 'high']);
  assert.equal(ths[4].children[0].textContent, '▼');
});

test('Key column sorts lexically ascending', () => {
  const ths = thead.children[0].children;
  fire(ths[0], 'click');
  assert.deepEqual(rowValues(tbody).map((r) => r[0]), ['c.note', 'f.alpha', 'k.zed']);
});

test('search filters rows with is-hidden and updates the n / N summary', () => {
  search.value = 'signed note';
  fire(search, 'input');
  const hidden = tbody.all.filter((n) => n.tagName === 'tr');
  const visibleRows = rowValues(tbody).filter((r) =>
    tbody.children.filter((tr) => !tr.classList.contains('is-hidden')).some((tr) => tr.children[0].textContent === r[0]),
  );
  assert.equal(hidden.filter((tr) => tr.classList.contains('is-hidden')).length, 2);
  assert.equal(visibleRows.length, 1);
  assert.equal(count.textContent, '1 / 3');
  search.value = ''; // type=search native clear button behaves like an empty value
  fire(search, 'input');
  assert.equal(tbody.all.filter((n) => n.tagName === 'tr' && n.classList.contains('is-hidden')).length, 0);
  assert.equal(count.textContent, '3 / 3');
});

test('whitespace-only query counts as cleared', () => {
  search.value = '   ';
  fire(search, 'input');
  assert.equal(count.textContent, '3 / 3');
});

test('all-zero confidence data skips the donut entirely, stats stay on', () => {
  openReport(FINDINGS2);
  const charts = ids['charts'];
  assert.equal(charts.hidden, false);
  assert.ok(charts.all.some((n) => n.classList.contains('stat-grid')), 'stat grid must render');
  assert.ok(!charts.all.some((n) => n.classList.contains('donut-box')), 'an empty donut is a claim, not decoration');
  // history has two fingerprint-findings series points -> sparkline present
  const spark = charts.all.find((n) => n.classList.contains('sparkline'));
  assert.ok(spark, 'two real history points must draw the sparkline');
});
