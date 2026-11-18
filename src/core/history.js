// 정책 변경 이력 (SPEC 2-5, 1-3-4). 항목 = { time(ISO8601), type, ruleNo, before, after, by }
//   type   : 'add' | 'update' | 'delete' | 'move'
//   ruleNo : 변경 대상 규칙의 '변경 전' 번호 (추가는 새로 붙은 번호)
//   before : 변경 전 규칙 전체 (추가는 null)
//   after  : 변경 후 규칙 전체 (삭제는 null). 이동은 before.no 와 after.no 가 각각 전·후 번호.
export const CHANGE_TYPES = ['add', 'update', 'delete', 'move'];
export const CHANGE_LABELS = { add: '추가', update: '수정', delete: '삭제', move: '이동' };

function clone(rule) {
  return rule === null || rule === undefined ? null : JSON.parse(JSON.stringify(rule));
}

export function makeEntry(change, now) {
  return {
    time: (now || (() => new Date().toISOString()))(),
    type: change.type,
    ruleNo: change.ruleNo,
    before: clone(change.before),
    after: clone(change.after),
    by: change.by,
  };
}

export function cloneHistory(entries) {
  return entries.map(e => ({ time: e.time, type: e.type, ruleNo: e.ruleNo, before: clone(e.before), after: clone(e.after), by: e.by }));
}
