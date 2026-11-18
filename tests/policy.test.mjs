import assert from 'assert';
import { test } from './helper.mjs';
import { defaultRules } from '../src/core/defaults.js';
import { Policy } from '../src/core/policy.js';

let tick;
function mk(rules) {
  tick = 0;
  return new Policy(rules, { by: 'tester', now: () => new Date(Date.UTC(2026, 10, 18, 0, 0, tick++)).toISOString() });
}
const web = { src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 8080', action: 'allow', purpose: '관리 콘솔' };
const nos = p => p.getRules().map(r => r.no);
const srcs = p => p.getRules().map(r => r.src + '>' + r.dst);

test('초기 정책표는 이력 없이 1..5 번호로 시작', () => {
  const p = mk();
  assert.deepStrictEqual(nos(p), [1, 2, 3, 4, 5]);
  assert.deepStrictEqual(p.getHistory(), []);
  assert.deepStrictEqual(p.check(), []);
});

test('추가(맨 아래): 번호 6, before=null, after=규칙 전체, ISO8601 시각, 변경자', () => {
  const p = mk();
  const r = p.addRule(web);
  assert.ok(r.ok);
  const h = p.getHistory();
  assert.strictEqual(h.length, 1);
  assert.strictEqual(h[0].type, 'add');
  assert.strictEqual(h[0].ruleNo, 6);
  assert.strictEqual(h[0].before, null);
  assert.deepStrictEqual(h[0].after, Object.assign({ no: 6 }, web));
  assert.strictEqual(h[0].by, 'tester');
  assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(h[0].time));
});

test('추가(위치 지정): 아래 규칙 번호가 밀리고 ruleNo 는 새 번호', () => {
  const p = mk();
  p.addRule(web, { position: 1, by: '홍길동' });
  assert.deepStrictEqual(nos(p), [1, 2, 3, 4, 5, 6]);
  assert.strictEqual(p.getRules()[0].service, 'TCP 8080');
  assert.strictEqual(p.getRules()[5].action, 'deny');       // 기본 거부는 6번으로 밀림
  const h = p.getHistory()[0];
  assert.strictEqual(h.ruleNo, 1);
  assert.strictEqual(h.by, '홍길동');                          // 호출별 변경자 지정
});

test('추가: 잘못된 입력은 거부하고 규칙·이력을 건드리지 않는다', () => {
  const p = mk();
  const r = p.addRule({ src: '없는곳', dst: 'DMZ', service: 'TCP x', action: 'allow', purpose: '' });
  assert.ok(!r.ok);
  assert.deepStrictEqual(r.errors, [{ field: 'src', error: '알 수 없는 주소' }, { field: 'service', error: '서비스 형식 오류' }]);
  assert.strictEqual(p.getRules().length, 5);
  assert.deepStrictEqual(p.getHistory(), []);
  assert.ok(!p.addRule(web, { position: 0 }).ok);
  assert.ok(!p.addRule(web, { position: 7 }).ok);
  assert.strictEqual(p.getHistory().length, 0);
});

test('수정: before/after 는 변경 전·후 규칙 전체', () => {
  const p = mk();
  const before = p.getRules()[3];
  const r = p.updateRule(4, { service: 'UDP 514' });
  assert.ok(r.ok && r.changed);
  const h = p.getHistory()[0];
  assert.strictEqual(h.type, 'update');
  assert.strictEqual(h.ruleNo, 4);
  assert.deepStrictEqual(h.before, before);
  assert.deepStrictEqual(h.after, Object.assign({}, before, { service: 'UDP 514' }));
  assert.strictEqual(p.getRules()[3].service, 'UDP 514');
});

test('수정: 바뀐 것이 없으면 이력을 남기지 않는다', () => {
  const p = mk();
  const r = p.updateRule(1, { src: '외부망', action: 'allow' });
  assert.ok(r.ok);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(p.getHistory().length, 0);
});

test('수정: 잘못된 값·없는 번호·번호 변경 시도는 거부', () => {
  const p = mk();
  const bad = p.updateRule(1, { dst: '??' });
  assert.deepStrictEqual(bad.errors, [{ field: 'dst', error: '알 수 없는 주소' }]);
  assert.strictEqual(p.getRules()[0].dst, 'DMZ 웹서버');          // 원래 값 유지
  assert.strictEqual(p.updateRule(99, { purpose: 'x' }).errors[0].error, '규칙 번호 없음');
  assert.strictEqual(p.updateRule(1, { no: 3 }).errors[0].error, '변경할 수 없는 항목');
  assert.strictEqual(p.getHistory().length, 0);
});

test('삭제: 번호 재배열, before=규칙 전체, after=null', () => {
  const p = mk();
  const target = p.getRules()[1];
  assert.ok(p.deleteRule(2).ok);
  assert.deepStrictEqual(nos(p), [1, 2, 3, 4]);
  assert.strictEqual(p.getRules()[1].src, '내부망 관리자 PC');       // 3번이 2번이 됨
  const h = p.getHistory()[0];
  assert.strictEqual(h.type, 'delete');
  assert.strictEqual(h.ruleNo, 2);
  assert.deepStrictEqual(h.before, target);
  assert.strictEqual(h.after, null);
  assert.strictEqual(p.deleteRule(9).errors[0].error, '규칙 번호 없음');
});

test('이동: 전·후 번호가 각각 before.no/after.no, ruleNo 는 이동 전 번호', () => {
  const p = mk();
  assert.ok(p.moveRule(5, 1).ok);                              // 기본 거부를 맨 위로
  assert.strictEqual(p.getRules()[0].action, 'deny');
  assert.deepStrictEqual(nos(p), [1, 2, 3, 4, 5]);
  const h = p.getHistory()[0];
  assert.strictEqual(h.type, 'move');
  assert.strictEqual(h.ruleNo, 5);
  assert.strictEqual(h.before.no, 5);
  assert.strictEqual(h.after.no, 1);
  assert.strictEqual(h.before.src, 'Any');
  assert.strictEqual(h.after.src, 'Any');
});

test('이동: 아래로 이동, 제자리, 범위 오류', () => {
  const p = mk();
  assert.ok(p.moveRule(1, 3).ok);
  assert.deepStrictEqual(srcs(p).slice(0, 3), ['DMZ 웹서버>내부망 DB 서버', '내부망 관리자 PC>개발·운영 서버', '외부망>DMZ 웹서버']);
  const n = p.getHistory().length;
  assert.deepStrictEqual(p.moveRule(2, 2), { ok: true, changed: false });
  assert.strictEqual(p.getHistory().length, n);                // 제자리는 이력 없음
  assert.strictEqual(p.moveRule(1, 0).errors[0].error, '위치 범위 오류');
  assert.strictEqual(p.moveRule(1, 6).errors[0].error, '위치 범위 오류');
  assert.strictEqual(p.moveRule(9, 1).errors[0].error, '규칙 번호 없음');
});

test('이동은 판정 결과를 바꾼다 (기본 거부를 맨 위로 올리면 1번 허용이 막힘)', () => {
  const p = mk();
  const pkt = { src: '203.0.113.10', dst: '172.16.10.10', proto: 'TCP', port: 443 };
  assert.strictEqual(p.judge(pkt).result.action, 'allow');
  p.moveRule(5, 1);
  const r = p.judge(pkt).result;
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 1);                         // 이제 1번이 기본 거부
  const f = p.check();
  assert.deepStrictEqual(f.filter(x => x.type === 'shadowing').map(x => x.no), [2, 3, 4, 5]); // 허용 4개가 모두 가려짐
});

test('이력은 변경 순서대로 쌓이고 시각이 증가한다', () => {
  const p = mk();
  p.addRule(web);
  p.updateRule(6, { purpose: '수정됨' });
  p.moveRule(6, 1);
  p.deleteRule(1);
  const h = p.getHistory();
  assert.deepStrictEqual(h.map(e => e.type), ['add', 'update', 'move', 'delete']);
  assert.deepStrictEqual(h.map(e => e.time), h.map(e => e.time).slice().sort());
  assert.strictEqual(new Set(h.map(e => e.time)).size, 4);
});

test('이력과 규칙은 바깥에서 고쳐도 내부에 영향이 없다', () => {
  const p = mk();
  p.addRule(web);
  p.getHistory()[0].after.src = '조작';
  p.getRules()[0].src = '조작';
  assert.strictEqual(p.getHistory()[0].after.src, '외부망');
  assert.strictEqual(p.getRules()[0].src, '외부망');
  const input = defaultRules();
  const q = mk(input);
  input[0].src = '조작';
  assert.strictEqual(q.getRules()[0].src, '외부망');
});

test('정책 점검(check): 함정 1 — 1번에 Any→Any 허용을 추가하면 차단 규칙이 섀도잉', () => {
  const p = mk();
  p.addRule({ src: 'Any', dst: 'Any', service: 'Any', action: 'allow', purpose: '' }, { position: 1 });
  const shadow = p.check().filter(x => x.type === 'shadowing');
  assert.deepStrictEqual(shadow.map(x => x.no), [6]);
});

test('정책 점검(check): 함정 3 — 수정으로 UDP 513 을 넣으면 경고, 514 로 되돌리면 경고 없음', () => {
  const p = mk();
  p.updateRule(4, { service: 'UDP 513, TCP 9200' });
  assert.deepStrictEqual(p.check().map(x => x.type), ['syslog-port']);
  p.updateRule(4, { service: 'UDP 514, TCP 9200' });
  assert.deepStrictEqual(p.check(), []);
  assert.strictEqual(p.getHistory().length, 2);                // 두 번 모두 수정 이력
});

test('판정(judge): 함정 2 와 입력 검증', () => {
  const p = mk();
  const r = p.judge({ src: '10.20.1.20', dst: '203.0.113.10', proto: 'TCP', port: 443 });
  assert.strictEqual(r.result.action, 'deny');
  assert.strictEqual(r.result.matched.no, 5);
  assert.deepStrictEqual(p.judge({ src: 'x', dst: '1.1.1.1', proto: 'TCP', port: 1 }), { ok: false, error: '알 수 없는 주소' });
});

test('스냅샷 저장·복원: 규칙과 이력이 그대로 돌아온다', () => {
  const p = mk();
  p.addRule(web);
  p.moveRule(6, 2);
  const json = JSON.stringify(p.snapshot());
  const q = Policy.restore(JSON.parse(json), { by: 'tester' });
  assert.deepStrictEqual(q.getRules(), p.getRules());
  assert.deepStrictEqual(q.getHistory(), p.getHistory());
  q.deleteRule(1);
  assert.strictEqual(q.getHistory().length, 3);                // 복원 후에도 계속 기록
});
