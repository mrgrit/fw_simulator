import assert from 'assert';
import { test } from './helper.mjs';
import { Policy } from '../src/core/policy.js';
import { SCENARIOS, describeJudge, findingsByRule, historyDiff, summarizeEntry, hostLabel, shortTime, traceLine } from '../src/ui/format.js';
import { parseImport, validateSnapshot, exportText, loadSnapshot, saveSnapshot, STORAGE_KEY } from '../src/ui/storage.js';

const web = { src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 8080', action: 'allow', purpose: '관리 콘솔' };

test('예제 패킷 7개가 기본 정책표에서 기대한 결과를 낸다', () => {
  const p = new Policy();
  for (const s of SCENARIOS) {
    const r = p.judge(s);
    assert.ok(r.ok, s.label);
    assert.strictEqual(r.result.action, s.expect.action, s.label);
    assert.strictEqual(r.result.matched.no, s.expect.no, s.label);
  }
});

test('describeJudge: 함정 2 문구', () => {
  const p = new Policy();
  const input = SCENARIOS[0];
  const d = describeJudge(p.judge(input).result, input);
  assert.strictEqual(d.headline, '차단 — 규칙 5 에 일치');
  assert.strictEqual(d.packetText, '개발 서버 (10.20.1.20) → 외부 사용자 (203.0.113.10)  TCP/443');
  assert.strictEqual(d.pathText, '개발·운영 서버망 → 방화벽 → 인터넷');
  assert.strictEqual(d.traceLines.length, 5);
  assert.strictEqual(d.traceLines[4], '5번  출발지 ✓  목적지 ✓  서비스 ✓  → 일치');
  assert.ok(d.stoppedNote.indexOf('first-match') !== -1);
});

test('describeJudge: 암묵적 차단은 경고와 함께', () => {
  const p = new Policy();
  p.deleteRule(5);
  const input = SCENARIOS[0];
  const d = describeJudge(p.judge(input).result, input);
  assert.strictEqual(d.headline, '차단 (암묵적 차단) — 일치하는 규칙 없음');
  assert.deepStrictEqual(d.warnings, ['일치 규칙 없음 — 기본 거부 규칙 필요']);
  assert.strictEqual(d.stoppedNote, '');
});

test('hostLabel / traceLine / shortTime', () => {
  assert.strictEqual(hostLabel('172.16.10.10'), '웹서버 (172.16.10.10)');
  assert.strictEqual(hostLabel('8.8.8.8'), '8.8.8.8');
  assert.strictEqual(traceLine({ no: 2, src: true, dst: false, svc: true, matched: false }), '2번  출발지 ✓  목적지 ✗  서비스 ✓  → 불일치');
  assert.strictEqual(shortTime('2026-11-18T00:00:03.123Z'), '2026-11-18 00:00:03');
  assert.strictEqual(shortTime('2026-11-18T00:00:03Z'), '2026-11-18 00:00:03');
});

test('findingsByRule: 규칙 번호별로 묶고 번호 없는 항목은 제외', () => {
  const m = findingsByRule([{ type: 'shadowing', no: 5 }, { type: 'redundancy', no: 5 }, { type: 'no-default-deny', no: null }]);
  assert.deepStrictEqual(Object.keys(m), ['5']);
  assert.strictEqual(m[5].length, 2);
  assert.deepStrictEqual(findingsByRule(null), {});
});

test('이력 문구: 추가·수정·삭제·이동', () => {
  const p = new Policy();
  p.addRule(web);
  p.updateRule(4, { service: 'UDP 513', purpose: '' });
  p.moveRule(6, 1);
  p.deleteRule(1);
  const h = p.getHistory();
  assert.strictEqual(summarizeEntry(h[0]), '규칙 6 추가: 외부망 → DMZ 웹서버 TCP 8080 허용');
  assert.strictEqual(summarizeEntry(h[1]), '규칙 4 수정: 서비스 UDP 514, TCP 9200 → UDP 513; 목적 로그 중앙 수집 → (비어 있음)');
  assert.strictEqual(summarizeEntry(h[2]), '규칙 6번 → 1번으로 이동 (외부망 → DMZ 웹서버 TCP 8080 허용)');
  assert.strictEqual(summarizeEntry(h[3]), '규칙 1 삭제: 외부망 → DMZ 웹서버 TCP 8080 허용');
  assert.deepStrictEqual(historyDiff(h[2]), [{ field: '번호', before: '6번', after: '1번' }]);
  assert.deepStrictEqual(historyDiff(h[1]).map(d => d.field), ['서비스', '목적']);
});

test('저장 스냅샷: 내보내기 → 가져오기 왕복', () => {
  const p = new Policy();
  p.addRule(web);
  p.moveRule(6, 2);
  const text = exportText(p.snapshot());
  const r = parseImport(text);
  assert.ok(r.ok);
  const q = Policy.restore(r.snapshot);
  assert.deepStrictEqual(q.getRules(), p.getRules());
  assert.deepStrictEqual(q.getHistory(), p.getHistory());
});

test('가져오기 검증: 잘못된 파일은 거부', () => {
  assert.strictEqual(parseImport('not json').error, 'JSON 을 읽을 수 없습니다');
  assert.strictEqual(parseImport('[]').error, '파일 형식이 올바르지 않습니다');
  assert.strictEqual(parseImport('{"version":2}').error, '지원하지 않는 버전입니다');
  assert.strictEqual(parseImport('{"version":1}').error, 'rules 항목이 없습니다');
  const good = new Policy().snapshot();
  const mut = f => { const s = JSON.parse(JSON.stringify(good)); f(s); return validateSnapshot(s); };
  assert.strictEqual(mut(s => { s.rules[0].src = '없는곳'; }).error, '규칙 1: 알 수 없는 주소');
  assert.strictEqual(mut(s => { s.rules[1].service = 'x'; }).error, '규칙 2: 서비스 형식 오류');
  assert.strictEqual(mut(s => { s.rules[2].action = 'maybe'; }).ok, false);
  assert.strictEqual(mut(s => { s.rules[0].purpose = 5; }).error, '규칙 1: 항목 형식 오류');
  assert.strictEqual(mut(s => { delete s.history; }).error, 'history 항목이 없습니다');
  assert.strictEqual(mut(s => { s.history = [{ type: 'zap' }]; }).error, '이력 1: 항목 형식 오류');
  assert.ok(mut(() => {}).ok);
});

test('저장소: 정상 저장·로드, 막혀 있거나 깨져 있어도 예외 없음', () => {
  const mem = { d: {}, getItem(k) { return k in this.d ? this.d[k] : null; }, setItem(k, v) { this.d[k] = v; } };
  const snap = new Policy().snapshot();
  assert.strictEqual(loadSnapshot(mem), null);
  assert.ok(saveSnapshot(mem, snap));
  assert.deepStrictEqual(loadSnapshot(mem), snap);
  const broken = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
  assert.strictEqual(loadSnapshot(broken), null);
  assert.strictEqual(saveSnapshot(broken, snap), false);
  mem.d[STORAGE_KEY] = '{깨진 JSON';
  assert.strictEqual(loadSnapshot(mem), null);
});
