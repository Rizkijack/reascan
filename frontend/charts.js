// reascan charts - SVG via createElementNS, themed through CSS variables.
// Zero dependencies; colors come from CSS classes style.css paints with var()
// (SVG presentation attributes do not reliably support var(), inline classes do).
// Everything is built from REAL report data by app.js; no mock series anywhere.

const NS = 'http://www.w3.org/2000/svg';

function svg(tag) {
  return document.createElementNS(NS, tag);
}

// Donut of an evidence/confidence distribution.
//   entries: Array<[key, count]> - zero-count keys are skipped by the caller.
// Center label shows the total. Returns the SVG node or null (nothing to draw).
export function buildDonut(entries, { size = 84, thickness = 9 } = {}) {
  const present = (entries ?? []).filter(([, n]) => n > 0);
  const total = present.reduce((sum, [, n]) => sum + n, 0);
  if (!total) return null;

  const r = (size - thickness) / 2;
  const c = size / 2;
  const circ = 2 * Math.PI * r;

  const s = svg('svg');
  s.setAttribute('viewBox', `0 0 ${size} ${size}`);
  s.setAttribute('width', size);
  s.setAttribute('height', size);
  s.setAttribute('role', 'img');
  s.setAttribute('class', 'donut');

  // background track, then one dash-array circle per segment
  const track = svg('circle');
  track.setAttribute('cx', c);
  track.setAttribute('cy', c);
  track.setAttribute('r', r);
  track.setAttribute('class', 'donut-track');
  s.append(track);

  let offset = 0; // 12 o'clock start, sweep clockwise
  for (const [key, n] of present) {
    const len = (n / total) * circ;
    const seg = svg('circle');
    seg.setAttribute('cx', c);
    seg.setAttribute('cy', c);
    seg.setAttribute('r', r);
    seg.setAttribute('class', `donut-seg donut-seg-${key}`);
    seg.setAttribute('stroke-dasharray', `${Math.max(len - 2, 0.5)} ${circ - Math.max(len - 2, 0.5)}`);
    seg.setAttribute('stroke-dashoffset', String(circ / 4 - offset));
    seg.setAttribute('stroke-linecap', 'butt');
    s.append(seg);
    offset += len;
  }

  const label = svg('text');
  label.setAttribute('x', c);
  label.setAttribute('y', c);
  label.setAttribute('text-anchor', 'middle');
  label.setAttribute('dominant-baseline', 'central');
  label.setAttribute('class', 'donut-total');
  label.textContent = String(total);
  s.append(label);

  return s;
}

// Sparkline over a numeric series (history-derived). A dashed-baseline grid,
// one normalized polyline, and a dot on the newest value. Fewer than 2 real
// numbers is a shapeless chart: return null so the caller skips it.
export function buildSparkline(series, { width = 120, height = 32 } = {}) {
  const points = (series ?? []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  if (points.length < 2) return null;

  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1; // flat series: park the line mid-height
  const pad = 2;

  const s = svg('svg');
  s.setAttribute('viewBox', `0 0 ${width} ${height}`);
  s.setAttribute('width', width);
  s.setAttribute('height', height);
  s.setAttribute('class', 'sparkline');
  s.setAttribute('aria-hidden', 'true');

  // two faint dashed gridlines at 1/3 and 2/3 height
  for (const y of [height / 3, (height * 2) / 3]) {
    const line = svg('line');
    line.setAttribute('x1', 0);
    line.setAttribute('y1', y);
    line.setAttribute('x2', width);
    line.setAttribute('y2', y);
    line.setAttribute('class', 'spark-grid');
    s.append(line);
  }

  const toXY = (v, i) => {
    const x = pad + (i / (points.length - 1)) * (width - pad * 2);
    const y = height - pad - ((v - min) / span) * (height - pad * 2);
    return [x.toFixed(1), y.toFixed(1)];
  };

  const polyline = svg('polyline');
  polyline.setAttribute('points', points.map((v, i) => toXY(v, i).join(',')).join(' '));
  polyline.setAttribute('class', 'spark-line');
  s.append(polyline);

  const [dx, dy] = toXY(points[points.length - 1], points.length - 1);
  const dot = svg('circle');
  dot.setAttribute('cx', dx);
  dot.setAttribute('cy', dy);
  dot.setAttribute('r', 2.2);
  dot.setAttribute('class', 'spark-dot');
  s.append(dot);

  return s;
}
