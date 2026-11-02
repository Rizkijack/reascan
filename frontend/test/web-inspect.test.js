import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

import { El, createDocument, fire, storageBean } from './dom-shim.js';

// app.js Web inspect section contract, driven through the real render path
// (history click -> render()). Pinned: the section is absent when the category
// was not requested, renders as a real table with the mono cells style.css
// styles, shows domain/listener/WebMCP/storage evidence, and never carries
// script source text - the suppressed inside the renderer is the guarantee.

const HERE = dirname(fileURLToPath(import.meta.url));
const appSource = readFileSync(join(HERE, '..', 'app.js'), 'utf8');

const webInspect = {
  scripts_total: 3,
  exported_scripts: 3,
  scripts: [
    { url: 'https://t.example/assets/app.js', is_module: true, length: 12000, source_map_url: 'https://t.example/assets/app.js.map', source_digest: 'aaaa1111bbbb2222' },
    { url: 'https://t.example/assets/app.js?x=1', is_module: false, length: 200, source_map_url: null, source_digest: null },
  ],
  // The renderer must only ever see this; the source text field the engine
  // hands over must never be shipped (adapter guard, pinned in reaCli tests).
  // This marker proves the frontend could not have copied it even by accident.
  retained_source_marker: 'SHOULD NEVER REACH THE PAGE',
  script_domain_counts: { 't.example': 2 },
  resource_type_counts: { Script: 2, Document: 1 },
  third_party: {
    approved_dom_urls: ['https://t.example/help'],
    outside_policy_dom_urls: ['https://analytics.example/collect'],
    third_party_domains: ['analytics.example'],
  },
  event_listeners: [
    { type: 'click', url: 'https://cdn.example/framework.js', line: 3, column: 4251 },
  ],
  webmcp_tools: [{ name: 'page.search', declared: true }],
  storage: { origin: 'https://t.example', usage_bytes: 0, quota_bytes: 76361915596, has_keys: false },
  workers: 0,
  console_events: 1,
  network_requests: 4,
  target: { title: 'Example page', url: 'https://t.example/', origin: 'https://t.example' },
};

const FINDINGS_EMPTY = {
  url: 'https://t.example/',
  timestamp: '2026-03-01T00:00:00Z',
  verdict: { confidence: 'high', limitations: [], unknowns: [] },
  fingerprint: { findings: [{ key: 'f.one', value: 1, type: 'observation', evidence: 'Seen', confidence: 'high' }] },
};

const FINDINGS = {
  url: 'https://t.example/',
  timestamp: '2026-03-01T00:00:00Z',
  verdict: { confidence: 'high', limitations: [], unknowns: [] },
  fingerprint: { findings: [{ key: 'f.one', value: 1, type: 'observation', evidence: 'Seen', confidence: 'high' }] },
  web_inspect: webInspect,
};

// The category WAS requested but every probe came back empty, and the adapter
// may still add fields the renderer has never heard of. The renderer must show
// the heading, render none of the empty sub-sections, and never echo unknown
// or score-like fields into the DOM.
const webInspectPartial = {
  scripts_total: null,
  exported_scripts: null,
  scripts: [],
  script_domain_counts: {},
  resource_type_counts: {},
  third_party: {},
  event_listeners: [],
  webmcp_tools: [],
  storage: null,
  workers: 0,
  console_events: 0,
  network_requests: 0,
  target: { title: null, url: null },
  limitations: [],
  unknown_envelope_field: { score: 42, junk: 'POISON_FOREIGN_FIELD' },
};

const FINDINGS_PARTIAL = {
  url: 'https://p.example/',
  timestamp: '2026-03-01T02:00:00Z',
  verdict: { confidence: 'low', limitations: [], unknowns: [] },
  fingerprint: { findings: [] },
  web_inspect: webInspectPartial,
};

const storage = storageBean();
storage.setItem('reascan:history', JSON.stringify([
  { url: FINDINGS.url, timestamp: FINDINGS.timestamp, confidence: 'high', findings: FINDINGS },
  { url: FINDINGS_EMPTY.url, timestamp: FINDINGS_EMPTY.timestamp, confidence: 'high', findings: FINDINGS_EMPTY },
  { url: FINDINGS_PARTIAL.url, timestamp: FINDINGS_PARTIAL.timestamp, confidence: 'low', findings: FINDINGS_PARTIAL },
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

await import('../app.js');

const historyButtons = ids['history-list'].all.filter((n) => n.classList.contains('history-open'));

const HISTORY = [FINDINGS, FINDINGS_EMPTY, FINDINGS_PARTIAL];

function renderReport(f) {
  fire(historyButtons[HISTORY.indexOf(f)], 'click');
  return ids['findings-body'];
}

test('the section does not render when the category was not requested', () => {
  const body = renderReport(FINDINGS_EMPTY); // findings.web_inspect is null
  assert.ok(!body.textContent.includes('Web inspect (REA)'), 'absent category must stay absent');
});

test('the section renders scripts as a real table with mono cells', () => {
  const body = renderReport(FINDINGS);
  assert.ok(body.textContent.includes('Web inspect (REA)'), 'the section must render');
  const table = body.all.find((n) => n.tagName === 'table' && n.textContent.includes('Script URL'));
  assert.ok(table, 'scripts must render as a table');
  const tbody = table.children.find((c) => c.tagName === 'tbody');
  assert.equal(tbody.children.length, 2, 'one row per distilled script');
  assert.ok(body.textContent.includes('aaaa1111bbbb2222'), 'digest is evidence, shown');
  assert.ok(tbody.children[0].all.some((n) => n.tagName === 'code'), 'URL and digest cells must be code elements');
});

test('mono styling for the cells comes from the existing report-table code rule', () => {
  const css = readFileSync(join(HERE, '..', 'style.css'), 'utf8');
  assert.ok(/\.report-table td code,/.test(css) || /\.report-table td code \{/.test(css),
    '.report-table td code must be (still) styled monospace');
  assert.ok(!/\.wi-/.test(css + appSource), 'no bespoke one-off CSS needed for this section');
});

test('third-party destinations render as domain chips', () => {
  const body = renderReport(FINDINGS);
  assert.ok(body.textContent.includes('Third-party destinations (1)'), 'labelled');
  const chip = body.all.find((n) => n.tagName === 'code' && n.textContent === 'analytics.example');
  assert.ok(chip, 'the third-party domain must be a chip');
});

test('event listeners show file:line:column, not a source snippet', () => {
  const body = renderReport(FINDINGS);
  assert.ok(body.textContent.includes('@ 3:4251'), `listener location expected, got: ${body.textContent}`);
  assert.ok(body.textContent.includes('cdn.example/framework.js'), 'listener script URL shown');
});

test('WebMCP names are labelled page-declared', () => {
  const body = renderReport(FINDINGS);
  assert.ok(body.textContent.includes('page.search (page-declared)'), 'declared tag travels with the name');
});

test('storage is meterless bytes with boolean key presence', () => {
  const body = renderReport(FINDINGS);
  assert.ok(/0 B used of 76361915596 B quota/.test(body.textContent), `bytes, not percent: ${body.textContent}`);
  assert.ok(body.textContent.includes('keys present: no'), 'boolean key presence, nothing more');
});

test('no source text ever reaches the report, and the renderer stays innerHTML-free', () => {
  const body = renderReport(FINDINGS);
  assert.ok(!body.textContent.includes('retained_source_marker'), 'the marker the adapter must strip stayed out');
  assert.ok(!/\.innerHTML\s*=/.test(appSource), 'app.js builds DOM, it never assigns innerHTML');
});

test('an empty-but-present category renders the heading only, foreign/score fields stay out', () => {
  const body = renderReport(FINDINGS_PARTIAL);
  assert.ok(body.textContent.includes('Web inspect (REA)'), 'a requested category must state itself');
  // Every empty sub-section stays absent rather than rendering an empty shell.
  assert.ok(!body.textContent.includes('Third-party destinations'), 'empty third-party list renders nothing');
  assert.ok(!body.textContent.includes('Event listeners'), 'empty listener list renders nothing');
  assert.ok(!body.textContent.includes('WebMCP tools'), 'empty WebMCP list renders nothing');
  assert.ok(!body.textContent.includes('keys present'), 'null storage renders no storage line');
  assert.ok(!body.all.some((n) => n.tagName === 'table'), 'zero scripts render no table');
  // Unknown adapter-side fields, including any score-shaped one, must not be
  // echoed - the renderer reads enumerated fields, never a lens of the payload.
  assert.ok(!body.textContent.includes('42'), 'a foreign score field must not surface anywhere');
  assert.ok(!body.textContent.includes('POISON_FOREIGN_FIELD'), 'unknown envelope fields never cross into the DOM');
});
