import assert from 'assert';
import { test } from './helper.mjs';
import { defaultRules } from '../src/core/defaults.js';
import { compileRules } from '../src/core/matcher.js';
import { parseAddress, parseService } from '../src/core/parse.js';
import { addressCovers, serviceCovers, analyze, WARN_NO_DEFAULT_DENY } from '../src/core/analyzer.js';

const rule = (no, src, dst, service, action, purpose) => ({ no, src, dst, service, action, purpose: purpose || '' });
const compiled = raws => { const c = compileRules(raws); assert.deepStrictEqual(c.errors, []); return c.rules; };
const A = s => parseAddress(s).value;
const S = s => parseService(s).value;
const types = f => f.map(x => x.type + ':' + x.no + (x.by ? '<' + x.by : ''));

// ---- covers ----
test('covers(주소): Any 규칙', () => {
  assert.ok(addressCovers(A('Any'), A('DMZ')));
  assert.ok(addressCovers(A('Any'), A('Any')));
  assert.ok(!addressCovers(A('DMZ'), A('Any')));
});

test('covers(주소): 구역은 그 구역의 IP·그룹을 덮지만 반대는 아니다', () => {
  assert.ok(addressCovers(A('내부망'), A('10.10.1.10')));
  assert.ok(addressCovers(A('내부망'), A('내부망 DB 서버')));
  assert.ok(addressCovers(A('내부망'), A('내부망')));
  assert.ok(!addressCovers(A('내부망 DB 서버'), A('내부망')));
  assert.ok(!addressCovers(A('DMZ 웹서버'), A('DMZ')));
  assert.ok(!addressCovers(A('내부망'), A('10.20.1.20')));
});

test('covers(주소): 그룹·IP 조합', () => {
  assert.ok(addressCovers(A('개발·운영 서버'), A('10.20.1.20')));
  assert.ok(!addressCovers(A('개발·운영 서버'), A('10.20.1.30')));
  assert.ok(addressCovers(A('내부 장비·DMZ'), A('DMZ 웹서버')));          // 구역이 IP 를 덮음
  assert.ok(addressCovers(A('내부 장비·DMZ'), A('내부망 관리자 PC')));
  assert.ok(!addressCovers(A('내부 장비·DMZ'), A('개발·운영 서버')));
  assert.ok(!addressCovers(A('내부 장비·DMZ'), A('외부망')));
  assert.ok(addressCovers(A('10.10.1.10'), A('내부망 관리자 PC')));       // 단일 IP 그룹
});

test('covers(서비스)', () => {
  assert.ok(serviceCovers(S('Any'), S('TCP 80')));
  assert.ok(!serviceCovers(S('TCP 80'), S('Any')));
  assert.ok(serviceCovers(S('TCP 80, 443'), S('TCP 443')));
  assert.ok(!serviceCovers(S('TCP 80'), S('TCP 80, 443')));
  assert.ok(serviceCovers(S('TCP 1-1024'), S('TCP 80, 443')));
  assert.ok(!serviceCovers(S('TCP 80'), S('UDP 80')));                    // 프로토콜이 다르면 덮지 못함
  assert.ok(serviceCovers(S('TCP 80, UDP 514'), S('UDP 514')));
  assert.ok(!serviceCovers(S('TCP 100-200'), S('TCP 150-250')));          // 일부만 겹침
});

// ---- 기본 정책표 ----
test('기본 정책표는 경고가 없다', () => {
  assert.deepStrictEqual(analyze(compiled(defaultRules())), []);
});

// ---- 2-2 기본 거부 ----
test('기본 거부: 마지막이 Any-Any-Any 차단이 아니면 경고', () => {
  const f = analyze(compiled(defaultRules().slice(0, 4)));
  assert.deepStrictEqual(types(f), ['no-default-deny:4']);
  assert.strictEqual(f[0].message, WARN_NO_DEFAULT_DENY);
});

test('기본 거부: 마지막 Any 규칙이 허용이거나 서비스가 Any 가 아니면 경고', () => {
  const base = defaultRules().slice(0, 4);
  assert.strictEqual(analyze(compiled(base.concat(rule(5, 'Any', 'Any', 'Any', 'allow')))).filter(x => x.type === 'no-default-deny').length, 1);
  assert.strictEqual(analyze(compiled(base.concat(rule(5, 'Any', 'Any', 'TCP 80', 'deny')))).filter(x => x.type === 'no-default-deny').length, 1);
  assert.strictEqual(analyze(compiled(base.concat(rule(5, 'Any', 'DMZ', 'Any', 'deny')))).filter(x => x.type === 'no-default-deny').length, 1);
});

test('기본 거부: 빈 정책표도 경고', () => {
  assert.deepStrictEqual(types(analyze([])), ['no-default-deny:null']);
});

// ---- 2-3 섀도잉 ----
test('함정 1: 1번이 Any→Any 허용이면 그 아래 차단 규칙(기본 거부 포함)은 모두 섀도잉', () => {
  const raws = [rule(1, 'Any', 'Any', 'Any', 'allow')].concat(defaultRules().slice(1).map((r, i) => Object.assign({}, r, { no: i + 2 })));
  // 2~4번은 허용, 5번은 차단. 차단 규칙은 모두 섀도잉이어야 한다.
  raws.push(rule(6, 'DMZ', 'Any', 'TCP 80', 'deny'));
  const f = analyze(compiled(raws));
  const shadow = f.filter(x => x.type === 'shadowing').map(x => x.no);
  assert.deepStrictEqual(shadow, [5, 6]);
  const msg = f.find(x => x.type === 'shadowing' && x.no === 5).message;
  assert.strictEqual(msg, '규칙 5 는 규칙 1 에 가려져 절대 적용되지 않습니다(섀도잉)');
  // 허용 규칙 2~4 는 1번과 같은 동작이므로 섀도잉이 아니라 중복이다.
  // 6번은 1번(허용)에게는 섀도잉, 5번(같은 차단)과는 중복이므로 두 경고가 모두 나온다.
  assert.deepStrictEqual(f.filter(x => x.type === 'redundancy').map(x => x.no + '<' + x.by), ['2<1', '3<1', '4<1', '6<5']);
});

test('섀도잉: 위 허용 규칙이 아래 더 좁은 차단 규칙을 덮음', () => {
  const f = analyze(compiled([
    rule(1, 'Any', 'DMZ', 'TCP 1-1024', 'allow'),
    rule(2, '외부망', 'DMZ 웹서버', 'TCP 443', 'deny'),
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(types(f), ['shadowing:2<1']);
});

test('섀도잉: 일부만 겹치면 섀도잉이 아니다', () => {
  const f = analyze(compiled([
    rule(1, 'Any', 'DMZ 웹서버', 'TCP 80', 'allow'),
    rule(2, 'Any', 'DMZ 웹서버', 'TCP 80, 443', 'deny'),  // 443 은 1번이 덮지 못함
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(f, []);
});

test('섀도잉: 위 규칙이 더 좁으면(아래가 더 넓으면) 섀도잉이 아니다', () => {
  const f = analyze(compiled([
    rule(1, 'DMZ 웹서버', '내부망 DB 서버', 'TCP 3306', 'deny'),
    rule(2, 'DMZ', '내부망', 'TCP 3306', 'allow'),
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(f, []);
});

test('섀도잉: 방향이 다르면 덮지 않는다', () => {
  const f = analyze(compiled([
    rule(1, '내부망', 'DMZ', 'Any', 'allow'),
    rule(2, 'DMZ', '내부망', 'Any', 'deny'),
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(f, []);
});

test('섀도잉: 위 규칙 번호가 여럿 덮으면 가장 먼저 찾은 규칙을 보고', () => {
  const f = analyze(compiled([
    rule(1, 'Any', 'DMZ', 'Any', 'allow'),
    rule(2, 'Any', 'DMZ', 'TCP 80', 'allow'),
    rule(3, 'Any', 'DMZ 웹서버', 'TCP 80', 'deny'),
    rule(4, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(types(f), ['redundancy:2<1', 'shadowing:3<1']);
});

// ---- 2-4 중복 ----
test('중복: 위 규칙이 아래 규칙을 덮고 동작이 같음', () => {
  const f = analyze(compiled([
    rule(1, 'Any', 'DMZ', 'TCP 80, 443', 'allow'),
    rule(2, '외부망', 'DMZ 웹서버', 'TCP 443', 'allow'),
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(types(f), ['redundancy:2<1']);
  assert.strictEqual(f[0].message, '규칙 2 는 규칙 1 와 중복입니다(같은 트래픽·같은 동작)');
});

test('중복: 완전히 같은 규칙 두 줄', () => {
  const f = analyze(compiled([
    rule(1, '외부망', 'DMZ 웹서버', 'TCP 80', 'allow'),
    rule(2, '외부망', 'DMZ 웹서버', 'TCP 80', 'allow'),
    rule(3, 'Any', 'Any', 'Any', 'deny'),
  ]));
  assert.deepStrictEqual(types(f), ['redundancy:2<1']);
});

// ---- 2-6 syslog ----
test('함정 3: syslog 규칙 포트를 UDP 513 으로 넣으면 경고, 514 면 경고 없음', () => {
  const mk = svc => compiled(defaultRules().map(r => (r.no === 4 ? Object.assign({}, r, { service: svc }) : r)));
  const bad = analyze(mk('UDP 513, TCP 9200'));
  assert.deepStrictEqual(types(bad), ['syslog-port:4']);
  assert.strictEqual(bad[0].message, '규칙 4: syslog 표준 포트가 아님 (UDP 513 → 표준 포트는 UDP 514)');
  assert.deepStrictEqual(analyze(mk('UDP 514, TCP 9200')), []);
});

test('syslog: 목적지가 SIEM 호스트 IP 여도 검사', () => {
  const f = analyze(compiled([rule(1, 'Any', '10.10.3.10', 'UDP 513', 'allow'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.deepStrictEqual(types(f), ['syslog-port:1']);
});

test('syslog: 목적에 syslog/로그 가 있으면 목적지와 무관하게 검사', () => {
  const f1 = analyze(compiled([rule(1, 'DMZ', '내부망', 'UDP 600', 'allow', 'syslog 수집'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.deepStrictEqual(types(f1), ['syslog-port:1']);
  const f2 = analyze(compiled([rule(1, 'DMZ', '내부망', 'UDP 600', 'allow', '로그 전송'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.deepStrictEqual(types(f2), ['syslog-port:1']);
  const f3 = analyze(compiled([rule(1, 'DMZ', '내부망', 'UDP 600', 'allow', '일반 연동'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.deepStrictEqual(f3, []);
});

test('syslog: 514 를 포함하는 범위나 Any 서비스는 경고 없음, UDP 없는 규칙은 검사 대상 아님', () => {
  const ok = (svc) => analyze(compiled([rule(1, 'DMZ', '보안관제(SIEM)', svc, 'allow'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.deepStrictEqual(ok('UDP 500-600'), []);
  assert.deepStrictEqual(ok('Any'), []);
  assert.deepStrictEqual(ok('TCP 9200'), []);
});

test('syslog: 여러 UDP 포트 중 514 가 없으면 모두 나열', () => {
  const f = analyze(compiled([rule(1, 'DMZ', '보안관제(SIEM)', 'UDP 513, 515', 'allow'), rule(2, 'Any', 'Any', 'Any', 'deny')]));
  assert.strictEqual(f[0].message, '규칙 1: syslog 표준 포트가 아님 (UDP 513, 515 → 표준 포트는 UDP 514)');
});
