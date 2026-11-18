import assert from 'assert';
import { test } from './helper.mjs';
import { defaultRules } from '../src/core/defaults.js';
import { compileRules, compileRule, parsePacket, evaluate, WARN_NO_MATCH } from '../src/core/matcher.js';

function table(raws) {
  const c = compileRules(raws || defaultRules());
  assert.deepStrictEqual(c.errors, []);
  return c.rules;
}
function judge(rules, src, dst, proto, port) {
  const p = parsePacket({ src, dst, proto, port });
  assert.ok(p.ok, JSON.stringify(p));
  return evaluate(rules, p.packet);
}
const rule = (no, src, dst, service, action) => ({ no, src, dst, service, action, purpose: '' });

test('기본 정책표 5행이 모두 해석된다', () => {
  const c = compileRules(defaultRules());
  assert.strictEqual(c.rules.length, 5);
  assert.deepStrictEqual(c.errors, []);
});

test('함정 2: 개발 서버→인터넷 TCP 443 은 5번 규칙에 걸려 차단', () => {
  const r = judge(table(), '10.20.1.20', '203.0.113.10', 'TCP', 443);
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 5);
  assert.strictEqual(r.implicit, false);
  assert.strictEqual(r.srcZone, '개발·운영 서버망');
  assert.strictEqual(r.dstZone, '인터넷');
});

test('1번: 외부 사용자→웹서버 TCP 80/443 허용, 8080 은 차단', () => {
  const rules = table();
  for (const port of [80, 443]) {
    const r = judge(rules, '203.0.113.10', '172.16.10.10', 'TCP', port);
    assert.strictEqual(r.action, 'allow');
    assert.strictEqual(r.matched.no, 1);
  }
  const r = judge(rules, '203.0.113.10', '172.16.10.10', 'TCP', 8080);
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 5);
});

test('1번: 웹서버가 아닌 DMZ 호스트(메일서버) 대상은 차단', () => {
  const r = judge(table(), '203.0.113.10', '172.16.10.20', 'TCP', 443);
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 5);
});

test('2번: 웹서버→DB 1433/3306 허용, 메일서버→DB 는 지정 IP 한정이라 차단', () => {
  const rules = table();
  assert.strictEqual(judge(rules, '172.16.10.10', '10.10.2.10', 'TCP', 3306).matched.no, 2);
  assert.strictEqual(judge(rules, '172.16.10.10', '10.10.2.10', 'TCP', 1433).action, 'allow');
  const r = judge(rules, '172.16.10.20', '10.10.2.10', 'TCP', 3306);
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 5);
});

test('3번: 관리자 PC→개발 서버 SSH 허용, 역방향과 다른 PC 는 차단', () => {
  const rules = table();
  assert.strictEqual(judge(rules, '10.10.1.10', '10.20.1.20', 'TCP', 22).action, 'allow');
  assert.strictEqual(judge(rules, '10.20.1.20', '10.10.1.10', 'TCP', 22).action, 'deny'); // 역방향
  assert.strictEqual(judge(rules, '10.10.1.11', '10.20.1.20', 'TCP', 22).action, 'deny'); // 지정 IP 아님
  assert.strictEqual(judge(rules, '10.10.1.10', '10.20.1.20', 'TCP', 23).action, 'deny'); // 포트 불일치
});

test('4번: SIEM 로그 수집 UDP 514 / TCP 9200 허용, TCP 514 는 차단', () => {
  const rules = table();
  assert.strictEqual(judge(rules, '172.16.10.10', '10.10.3.10', 'UDP', 514).matched.no, 4);
  assert.strictEqual(judge(rules, '10.10.2.10', '10.10.3.10', 'TCP', 9200).action, 'allow');
  assert.strictEqual(judge(rules, '172.16.10.10', '10.10.3.10', 'TCP', 514).action, 'deny');
  assert.strictEqual(judge(rules, '172.16.10.10', '10.10.3.10', 'UDP', 513).action, 'deny');
});

test('first-match: 허용 아래에 같은 범위의 차단이 있어도 결과는 허용', () => {
  const rules = table([
    rule(1, 'Any', 'DMZ 웹서버', 'TCP 80', 'allow'),
    rule(2, 'Any', 'DMZ 웹서버', 'TCP 80', 'deny'),
  ]);
  const r = judge(rules, '203.0.113.10', '172.16.10.10', 'TCP', 80);
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.matched.no, 1);
});

test('first-match: 순서를 바꾸면 결과가 바뀐다 (번호가 위치를 정한다)', () => {
  const a = rule(1, 'Any', 'DMZ 웹서버', 'TCP 80', 'allow');
  const b = rule(2, 'Any', 'DMZ 웹서버', 'TCP 80', 'deny');
  assert.strictEqual(judge(table([a, b]), '203.0.113.10', '172.16.10.10', 'TCP', 80).action, 'allow');
  const a2 = Object.assign({}, a, { no: 2 });
  const b2 = Object.assign({}, b, { no: 1 });
  assert.strictEqual(judge(table([a2, b2]), '203.0.113.10', '172.16.10.10', 'TCP', 80).action, 'deny');
});

test('first-match: 배열 순서가 아니라 번호 오름차순으로 비교한다', () => {
  const rules = table([rule(5, 'Any', 'Any', 'Any', 'deny'), rule(1, 'Any', 'Any', 'Any', 'allow')]);
  assert.strictEqual(rules[0].no, 1);
  assert.strictEqual(judge(rules, '203.0.113.10', '10.10.2.10', 'TCP', 1).action, 'allow');
});

test('첫 일치에서 멈춘다: trace 는 일치 규칙까지만', () => {
  const r = judge(table(), '203.0.113.10', '172.16.10.10', 'TCP', 443);
  assert.deepStrictEqual(r.trace.map(t => t.no), [1]);
  assert.ok(r.trace[0].matched);
  const r2 = judge(table(), '10.20.1.20', '203.0.113.10', 'TCP', 443);
  assert.deepStrictEqual(r2.trace.map(t => t.no), [1, 2, 3, 4, 5]);
  assert.ok(r2.trace.slice(0, 4).every(t => !t.matched));
});

test('일치 규칙 없음 = 암묵적 차단 + 경고 (기본 거부 규칙 없는 표)', () => {
  const rules = table(defaultRules().slice(0, 4));
  const r = judge(rules, '10.20.1.20', '203.0.113.10', 'TCP', 443);
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched, null);
  assert.strictEqual(r.implicit, true);
  assert.deepStrictEqual(r.warnings, [WARN_NO_MATCH]);
});

test('빈 정책표도 암묵적 차단', () => {
  const r = judge([], '10.10.1.10', '10.20.1.20', 'TCP', 22);
  assert.strictEqual(r.action, 'deny');
  assert.ok(r.implicit);
});

test('정상 판정은 경고가 없다', () => {
  const r = judge(table(), '203.0.113.10', '172.16.10.10', 'TCP', 443);
  assert.deepStrictEqual(r.warnings, []);
  assert.strictEqual(r.implicit, false);
});

test('함정 1 전제: 1번이 Any→Any 허용이면 모든 패킷이 허용된다', () => {
  const rules = table([rule(1, 'Any', 'Any', 'Any', 'allow'), ...defaultRules().slice(1)].map((r, i) => Object.assign({}, r, { no: i + 1 })));
  const r = judge(rules, '10.20.1.20', '203.0.113.10', 'TCP', 443);
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.matched.no, 1);
});

test('compileRule: 잘못된 필드는 오류 문구와 함께 거부', () => {
  const r = compileRule({ no: 1, src: '없는곳', dst: 'DMZ', service: 'TCP x', action: 'allow' });
  assert.ok(!r.ok);
  assert.deepStrictEqual(r.errors, [
    { field: 'src', error: '알 수 없는 주소' },
    { field: 'service', error: '서비스 형식 오류' },
  ]);
  const bad = compileRules([rule(1, 'Any', 'Any', 'Any', 'maybe')]);
  assert.strictEqual(bad.rules.length, 0);
  assert.strictEqual(bad.errors[0].field, 'action');
});

test('parsePacket: 입력 검증', () => {
  assert.strictEqual(parsePacket({ src: '1.2.3', dst: '10.10.1.1', proto: 'TCP', port: 80 }).error, '알 수 없는 주소');
  assert.strictEqual(parsePacket({ src: '10.10.1.1', dst: 'DMZ', proto: 'TCP', port: 80 }).error, '알 수 없는 주소');
  for (const [proto, port] of [['ICMP', 80], ['TCP', 0], ['TCP', 70000], ['TCP', 'abc'], ['TCP', 1.5], ['', 80]]) {
    assert.strictEqual(parsePacket({ src: '10.10.1.1', dst: '10.10.1.2', proto, port }).error, '서비스 형식 오류', proto + port);
  }
  const ok = parsePacket({ src: '10.10.1.1', dst: '10.10.1.2', proto: 'tcp', port: '443' });
  assert.ok(ok.ok);
  assert.strictEqual(ok.packet.proto, 'TCP');
  assert.strictEqual(ok.packet.port, 443);
});
