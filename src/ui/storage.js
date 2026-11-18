// 저장·내보내기·가져오기. 저장소가 막혀 있어도(시크릿 창 등) 예외 없이 동작해야 한다.
import { compileRule } from '../core/matcher.js';
import { CHANGE_TYPES } from '../core/history.js';

export const STORAGE_KEY = 'fw_simulator.snapshot.v1';
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);

// 스냅샷 { version:1, rules:[...], history:[...] } 의 구조와 규칙 내용을 검사한다.
export function validateSnapshot(s) {
  if (!isObj(s)) return { ok: false, error: '파일 형식이 올바르지 않습니다' };
  if (s.version !== 1) return { ok: false, error: '지원하지 않는 버전입니다' };
  if (!Array.isArray(s.rules)) return { ok: false, error: 'rules 항목이 없습니다' };
  for (let i = 0; i < s.rules.length; i++) {
    const r = s.rules[i];
    if (!isObj(r) || ['src', 'dst', 'service', 'purpose'].some(k => typeof r[k] !== 'string')) {
      return { ok: false, error: `규칙 ${i + 1}: 항목 형식 오류` };
    }
    const c = compileRule(Object.assign({}, r, { no: i + 1 }));
    if (!c.ok) return { ok: false, error: `규칙 ${i + 1}: ` + c.errors.map(e => e.error).join(', ') };
  }
  if (!Array.isArray(s.history)) return { ok: false, error: 'history 항목이 없습니다' };
  for (let i = 0; i < s.history.length; i++) {
    const e = s.history[i];
    const okRule = v => v === null || isObj(v);
    if (!isObj(e) || CHANGE_TYPES.indexOf(e.type) === -1 || typeof e.time !== 'string' || typeof e.by !== 'string'
        || !Number.isInteger(e.ruleNo) || !okRule(e.before) || !okRule(e.after)) {
      return { ok: false, error: `이력 ${i + 1}: 항목 형식 오류` };
    }
  }
  return { ok: true };
}

export function parseImport(text) {
  let obj;
  try { obj = JSON.parse(text); } catch (e) { return { ok: false, error: 'JSON 을 읽을 수 없습니다' }; }
  const v = validateSnapshot(obj);
  return v.ok ? { ok: true, snapshot: obj } : v;
}

export function exportText(snapshot) { return JSON.stringify(snapshot, null, 2); }

export function loadSnapshot(storage) {
  try {
    const t = storage.getItem(STORAGE_KEY);
    if (!t) return null;
    const p = parseImport(t);
    return p.ok ? p.snapshot : null;
  } catch (e) { return null; }
}

export function saveSnapshot(storage, snapshot) {
  try { storage.setItem(STORAGE_KEY, JSON.stringify(snapshot)); return true; } catch (e) { return false; }
}
