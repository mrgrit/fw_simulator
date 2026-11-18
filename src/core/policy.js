// 정책표 관리: 규칙 추가·수정·삭제·이동. 모든 변경은 이력에 자동 기록된다 (SPEC 2-5).
// 규칙 번호는 위→아래 위치(1..n)이며 변경 후 항상 연속 번호로 다시 매겨진다.
// 규칙 형식: { no, src, dst, service, action: 'allow'|'deny', purpose }
import { defaultRules } from './defaults.js';
import { compileRule, compileRules, parsePacket, evaluate } from './matcher.js';
import { analyze } from './analyzer.js';
import { makeEntry, cloneHistory } from './history.js';

export const EDITABLE = ['src', 'dst', 'service', 'action', 'purpose'];
export const ERR_NO_RULE = '규칙 번호 없음';
export const ERR_POSITION = '위치 범위 오류';

function normalize(fields) {
  const r = {};
  for (const k of EDITABLE) {
    const v = fields[k];
    r[k] = typeof v === 'string' ? v.trim() : (k === 'purpose' ? '' : v);
  }
  return r;
}

export class Policy {
  // rules: 초기 정책표(이력에 남기지 않음), opts: { by(기본 변경자), now(시계 함수, 테스트용), topo }
  constructor(rules, opts) {
    const o = opts || {};
    this.by = o.by || '관리자';
    this.now = o.now || null;
    this.topo = o.topo || undefined;
    const base = (rules || defaultRules()).map(r => Object.assign({ no: 0 }, normalize(r)));
    this._rules = base;
    this._history = [];
    this._renumber();
  }

  _renumber() { this._rules.forEach((r, i) => { r.no = i + 1; }); }
  _find(no) { return this._rules.findIndex(r => r.no === no); }
  _log(type, ruleNo, before, after, by) {
    const entry = makeEntry({ type, ruleNo, before, after, by: by || this.by }, this.now);
    this._history.push(entry);
    return JSON.parse(JSON.stringify(entry));
  }
  _validate(rule) {
    const c = compileRule(rule, this.topo);
    return c.ok ? null : c.errors;
  }

  getRules() { return this._rules.map(r => Object.assign({}, r)); }
  getHistory() { return cloneHistory(this._history); }

  // 추가: opts { position(1..n+1, 기본 맨 아래), by }
  addRule(fields, opts) {
    const o = opts || {};
    const pos = o.position === undefined ? this._rules.length + 1 : o.position;
    if (!Number.isInteger(pos) || pos < 1 || pos > this._rules.length + 1) return { ok: false, errors: [{ field: 'position', error: ERR_POSITION }] };
    const rule = Object.assign({ no: pos }, normalize(fields));
    const errors = this._validate(rule);
    if (errors) return { ok: false, errors };
    this._rules.splice(pos - 1, 0, rule);
    this._renumber();
    const entry = this._log('add', pos, null, rule, o.by);
    return { ok: true, rule: Object.assign({}, rule), entry };
  }

  // 수정: changes 에는 EDITABLE 항목만 허용(번호 변경은 moveRule). 바뀐 것이 없으면 이력을 남기지 않는다.
  updateRule(no, changes, opts) {
    const o = opts || {};
    const ix = this._find(no);
    if (ix === -1) return { ok: false, errors: [{ field: 'no', error: ERR_NO_RULE }] };
    const bad = Object.keys(changes).filter(k => EDITABLE.indexOf(k) === -1);
    if (bad.length) return { ok: false, errors: bad.map(k => ({ field: k, error: '변경할 수 없는 항목' })) };
    const before = Object.assign({}, this._rules[ix]);
    const after = Object.assign({}, before, normalize(Object.assign({}, before, changes)));
    const errors = this._validate(after);
    if (errors) return { ok: false, errors };
    if (EDITABLE.every(k => before[k] === after[k])) return { ok: true, changed: false, rule: before };
    this._rules[ix] = after;
    const entry = this._log('update', no, before, after, o.by);
    return { ok: true, changed: true, rule: Object.assign({}, after), entry };
  }

  deleteRule(no, opts) {
    const o = opts || {};
    const ix = this._find(no);
    if (ix === -1) return { ok: false, errors: [{ field: 'no', error: ERR_NO_RULE }] };
    const before = Object.assign({}, this._rules[ix]);
    this._rules.splice(ix, 1);
    this._renumber();
    const entry = this._log('delete', no, before, null, o.by);
    return { ok: true, entry };
  }

  // 이동: no 번 규칙을 toNo 번 위치로 옮긴다 (사이 규칙들은 한 칸씩 밀린다).
  moveRule(no, toNo, opts) {
    const o = opts || {};
    const ix = this._find(no);
    if (ix === -1) return { ok: false, errors: [{ field: 'no', error: ERR_NO_RULE }] };
    if (!Number.isInteger(toNo) || toNo < 1 || toNo > this._rules.length) return { ok: false, errors: [{ field: 'position', error: ERR_POSITION }] };
    if (toNo === no) return { ok: true, changed: false };
    const before = Object.assign({}, this._rules[ix]);
    const moved = this._rules.splice(ix, 1)[0];
    this._rules.splice(toNo - 1, 0, moved);
    this._renumber();
    const after = Object.assign({}, this._rules[toNo - 1]);
    const entry = this._log('move', no, before, after, o.by);
    return { ok: true, changed: true, entry };
  }

  // ---- 판정·점검 (matcher, analyzer 연결) ----
  compile() { return compileRules(this._rules, this.topo); }
  check() { return analyze(this.compile().rules, this.topo); }
  judge(input) {
    const p = parsePacket(input);
    if (!p.ok) return { ok: false, error: p.error };
    return { ok: true, result: evaluate(this.compile().rules, p.packet, this.topo) };
  }

  // ---- 저장·복원 (localStorage / JSON 파일용) ----
  snapshot() { return { version: 1, rules: this.getRules(), history: this.getHistory() }; }
  static restore(snap, opts) {
    const p = new Policy(snap.rules, opts);
    p._history = cloneHistory(snap.history || []);
    return p;
  }
}
