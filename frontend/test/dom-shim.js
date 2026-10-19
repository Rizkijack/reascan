// Shared minimal DOM shim for node --test (same mindset as smoke-all.mjs step 6,
// but reusable and extended for the app.js sortable table: move-on-reappend
// ordering, classList, attributes, and a tiny querySelectorAll).
// It proves wiring and behavior, not pixels.

export class El {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.handlers = {};
    this.attrs = {};
    this.dataset = {};
    this._text = '';
    this.className = '';
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.type = '';
    this.checked = false;
    this.classList = {
      add: (...cs) => {
        this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...cs])].join(' ');
      },
      remove: (...cs) => {
        this.className = this.className.split(/\s+/).filter((c) => c && !cs.includes(c)).join(' ');
      },
      toggle: (c, force) => {
        const has = this.classList.contains(c);
        const want = force === undefined ? !has : !!force;
        if (want && !has) this.classList.add(c);
        if (!want && has) this.classList.remove(c);
        return want;
      },
      contains: (c) => this.className.split(/\s+/).includes(c),
    };
  }

  // _text + children textContent so nested chips (td > span.chip) read through.
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v ?? ''); this.children = []; }

  // Re-appending an existing child must MOVE it to the end (like a real DOM);
  // the sortable table relies on this for its ordered tbody.
  append(...nodes) {
    for (const n of nodes) {
      if (n == null) continue;
      const kids = n.isFragment ? (this.children.push(...n.children), n.children = [], null) : n;
      if (!kids) continue;
      const old = kids.__parent;
      if (old) {
        const i = old.children.indexOf(kids);
        if (i >= 0) old.children.splice(i, 1);
      }
      kids.__parent = this;
      this.children.push(kids);
    }
    return this;
  }
  appendChild(n) { this.append(n); return n; }

  setAttribute(k, v) {
    this.attrs[k] = String(v);
    if (k === 'class') this.className = String(v); // SVG charts paint via class attrs
  }
  getAttribute(k) { return (k in this.attrs) ? this.attrs[k] : null; }

  addEventListener(type, fn) { (this.handlers[type] ??= []).push(fn); }
  removeEventListener(type, fn) { this.handlers[type] = (this.handlers[type] ?? []).filter((f) => f !== fn); }
  fire(type, event = {}) { for (const fn of [...(this.handlers[type] ?? [])]) fn(event); }
  scrollIntoView() {}

  get all() {
    const out = [];
    for (const c of this.children) {
      if (c.all) { out.push(c); out.push(...c.all); }
      else out.push(c);
    }
    return out;
  }

  // Tiny matcher: 'button[data-mode]', 'th', 'td.type', 'span.sort-glyph'.
  querySelectorAll(selector) {
    const attrs = [...selector.matchAll(/\[([^\]]+)\]/g)].map((m) => m[1]);
    const base = selector.replace(/\[[^\]]+\]/g, '');
    const [tag, ...classes] = base.split('.');
    return this.all.filter((n) => {
      if (!n.querySelectorAll) return false;
      if (tag && n.tagName !== tag) return false;
      for (const cls of classes) if (!n.classList.contains(cls)) return false;
      for (const a of attrs) {
        const eq = a.indexOf('=');
        const key = eq === -1 ? a : a.slice(0, eq);
        const val = eq === -1 ? undefined : a.slice(eq + 1).replace(/^["']|["']$/g, '');
        const got = key.startsWith('data-') ? n.dataset[key.slice(5)] : n.attrs[key];
        if (val === undefined ? got == null : got !== String(val)) return false;
      }
      return true;
    });
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] ?? null; }
}

export const textNode = (t) => { const e = new El('#text'); e.textContent = t; return e; };
export const fragment = () => ({ isFragment: true, children: [], append(...n) { this.children.push(...n.flatMap((x) => (x?.isFragment ? x.children : [x]))); } });

// document factory. readyState defaults to 'loading' so module-level *Auto-boot*
// branches (theme.js / bg3d.js DOMContentLoaded) only register and never fire -
// tests then drive the exported functions themselves.
export function createDocument({ ids = {}, readyState = 'loading', documentElement = new El('html') } = {}) {
  const doc = {
    readyState,
    documentElement,
    hidden: false,
    _listeners: {},
    addEventListener(type, fn) { (doc._listeners[type] ??= []).push(fn); },
    removeEventListener(type, fn) { doc._listeners[type] = (doc._listeners[type] ?? []).filter((f) => f !== fn); },
    getElementById: (id) => ids[id] ?? null,
    createElement: (tag) => new El(tag),
    createElementNS: (_ns, tag) => new El(tag),
    createTextNode: textNode,
    createDocumentFragment: fragment,
    querySelectorAll: () => [],
  };
  if (typeof documentElement === 'object') documentElement.dataset ??= {};
  return doc;
}

export const fire = (el, type, event = {}) => el.fire(type, event);
export const fireDocument = (doc, type) => { for (const fn of [...(doc._listeners[type] ?? [])]) fn(); };

// In-memory localStorage with the exact surface the modules touch.
export const storageBean = () => {
  const map = new Map();
  return {
    map,
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
  };
};
