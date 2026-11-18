// SPEC 3절 '함정 테스트 (교수자)' 3개를 한 곳에 모아 둔 인수 테스트. Policy 공개 API 만 사용한다.
import assert from 'assert';
import { test } from './helper.mjs';
import { Policy } from '../src/core/policy.js';

test('SPEC 3-1 함정 1: 1번이 Any→Any 허용이면 그 아래 차단 규칙은 모두 섀도잉 경고', () => {
  const p = new Policy();
  p.addRule({ src: 'Any', dst: 'Any', service: 'Any', action: 'allow', purpose: '실수로 넣은 전체 허용' }, { position: 1 });
  const shadowed = p.check().filter(f => f.type === 'shadowing');
  const denyNos = p.getRules().filter(r => r.action === 'deny').map(r => r.no);
  assert.deepStrictEqual(shadowed.map(f => f.no), denyNos);          // 차단 규칙 전부(기본 거부 포함)
  assert.ok(shadowed.every(f => f.by === 1));
});

test('SPEC 3-2 함정 2: 개발 서버(10.20.1.20)→인터넷(203.0.113.10) TCP 443 은 5번 규칙에 걸려 차단', () => {
  const r = new Policy().judge({ src: '10.20.1.20', dst: '203.0.113.10', proto: 'TCP', port: 443 }).result;
  assert.strictEqual(r.action, 'deny');
  assert.strictEqual(r.matched.no, 5);
});

test('SPEC 3-3 함정 3: syslog 규칙 UDP 513 은 경고, 514 는 경고 없음', () => {
  const p = new Policy();
  p.updateRule(4, { service: 'UDP 513' });
  const w = p.check();
  assert.strictEqual(w.length, 1);
  assert.strictEqual(w[0].message, '규칙 4: syslog 표준 포트가 아님 (UDP 513 → 표준 포트는 UDP 514)');
  p.updateRule(4, { service: 'UDP 514' });
  assert.deepStrictEqual(p.check(), []);
});
