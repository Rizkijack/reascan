import { test } from 'node:test';
import assert from 'node:assert/strict';
import { El, createDocument } from './dom-shim.js';

// charts.js contract: builds only from real data, returns null when the data is
// too thin to chart honestly, and paints with CSS classes (var()-tokens) - never
// a hardcoded fill/stroke hex.

const mod = () => import('../charts.js');

function renderDoc() {
  globalThis.document = createDocument({});
}

test('buildDonut returns null for empty / zero-total entries (no div-by-zero)', async () => {
  const { buildDonut } = await mod();
  renderDoc();
  assert.equal(buildDonut([]), null);
  assert.equal(buildDonut(null), null);
  assert.equal(buildDonut([['high', 0], ['medium', 0], ['low', 0]]), null);
});

test('buildDonut skips zero entries and draws exactly one seg per present entry', async () => {
  const { buildDonut } = await mod();
  renderDoc();
  const svg = buildDonut([['high', 2], ['medium', 1], ['low', 0]]);
  assert.ok(svg, 'a non-zero total must produce a chart');
  assert.equal(svg.getAttribute('viewBox'), '0 0 84 84');
  const segs = svg.children.filter((c) => c.getAttribute?.('class')?.includes('donut-seg'));
  assert.equal(segs.length, 2);
  assert.equal(segs[0].getAttribute('class'), 'donut-seg donut-seg-high');
  assert.equal(segs[1].getAttribute('class'), 'donut-seg donut-seg-medium');
  const label = svg.children.find((c) => c.getAttribute?.('class') === 'donut-total');
  assert.equal(label.textContent, '3');
});

test('buildDonut paints via CSS classes, not hardcoded fill/stroke', async () => {
  const { buildDonut } = await mod();
  renderDoc();
  const svg = buildDonut([['high', 1]]);
  for (const node of [...svg.children]) {
    assert.equal(node.getAttribute('fill'), null);
    assert.equal(node.getAttribute('stroke'), null);
    assert.equal(node.getAttribute('style'), null);
  }
  const seg = svg.children.find((c) => c.getAttribute?.('class') === 'donut-seg donut-seg-high');
  assert.equal(seg.getAttribute('fill'), null);
});

test('buildSparkline returns null below 2 real points (incl. NaN/Infinity noise)', async () => {
  const { buildSparkline } = await mod();
  renderDoc();
  assert.equal(buildSparkline([]), null);
  assert.equal(buildSparkline(null), null);
  assert.equal(buildSparkline([5]), null);
  assert.equal(buildSparkline([5, NaN]), null); // only one real point after filter
  assert.equal(buildSparkline([5, Infinity]), null);
  assert.equal(buildSparkline(['a', 3]), null);
});

test('buildSparkline draws a polyline over real points, dot on the newest', async () => {
  const { buildSparkline } = await mod();
  renderDoc();
  const svg = buildSparkline([3, 7], { width: 120, height: 32 });
  assert.ok(svg);
  assert.equal(svg.getAttribute('aria-hidden'), 'true');
  const line = svg.children.find((c) => c.getAttribute?.('class') === 'spark-line');
  const pts = line.getAttribute('points').split(' ');
  assert.equal(pts.length, 2);
  // pad=2: x runs 2 -> 118
  assert.match(pts[0], /^2\.0,/);
  assert.match(pts[1], /^118\.0,/);
  const dot = svg.children.find((c) => c.tagName === 'circle');
  assert.match(dot.getAttribute('cx'), /^118\.0$/);
});

test('buildSparkline flat series parks mid-height (no NaN from span=0)', async () => {
  const { buildSparkline } = await mod();
  renderDoc();
  const svg = buildSparkline([4, 4]);
  const line = svg.children.find((c) => c.getAttribute?.('class') === 'spark-line');
  assert.ok(!line.getAttribute('points').includes('NaN'));
});
