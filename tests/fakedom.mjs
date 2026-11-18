// 테스트용 최소 가짜 DOM. main.js 가 쓰는 API(createElement, appendChild, textContent, 이벤트 등)만 구현한다.
export class FakeText { constructor(d) { this.nodeType = 3; this.data = d; } }

export class FakeNode {
  constructor(tag) {
    this.nodeType = 1; this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {};
    this.className = ''; this.value = ''; this.hidden = false; this.disabled = false; this.id = ''; this.type = '';
  }
  appendChild(c) {
    this.children.push(c);
    if (this.tagName === 'SELECT' && this.value === '' && c.tagName === 'OPTION' && c.value !== '') this.value = c.value; // 첫 option 이 기본 선택
    return c;
  }
  get textContent() { return this.children.map(c => (c.nodeType === 3 ? c.data : c.textContent)).join(''); }
  set textContent(v) { this.children = []; if (v !== '' && v !== null && v !== undefined) this.children.push(new FakeText(String(v))); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  click() { fire(this, 'click'); }
}

export function fire(node, type, extra) {
  const ev = Object.assign({ type, target: node, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } }, extra || {});
  (node.listeners[type] || []).forEach(fn => fn(ev));
  return ev;
}

export function walk(node, fn) {
  if (node.nodeType !== 1) return;
  fn(node);
  node.children.forEach(c => walk(c, fn));
}
export function findAll(node, pred) { const out = []; walk(node, n => { if (pred(n)) out.push(n); }); return out; }

export function makeDoc() {
  const root = new FakeNode('div');
  root.id = 'app';
  const doc = {
    root,
    createElement: t => new FakeNode(t),
    createTextNode: d => new FakeText(d),
    getElementById: id => findAll(root, n => n.id === id)[0] || null,
  };
  return doc;
}

export function memStorage() {
  return { d: {}, getItem(k) { return k in this.d ? this.d[k] : null; }, setItem(k, v) { this.d[k] = v; } };
}
