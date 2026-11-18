import assert from 'assert';
import { test } from './helper.mjs';
import { parseIPv4, formatIPv4, parseCIDR, cidrContains, zoneOf, defaultTopology } from '../src/core/topology.js';

const ip = s => parseIPv4(s);

test('IPv4 파싱: 올바른 주소', () => {
  assert.strictEqual(ip('0.0.0.0'), 0);
  assert.strictEqual(ip('255.255.255.255'), 4294967295);
  assert.strictEqual(formatIPv4(ip('10.20.1.20')), '10.20.1.20');
});

test('IPv4 파싱: 틀린 주소는 null', () => {
  for (const bad of ['', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', 'a.b.c.d', '1.2.3.-4', ' ', null, undefined]) {
    assert.strictEqual(ip(bad), null, String(bad));
  }
});

test('CIDR 포함 판정', () => {
  assert.ok(cidrContains('10.10.0.0/16', ip('10.10.255.255')));
  assert.ok(!cidrContains('10.10.0.0/16', ip('10.11.0.0')));
  assert.ok(cidrContains('172.16.10.0/24', ip('172.16.10.0')));
  assert.ok(!cidrContains('172.16.10.0/24', ip('172.16.11.0')));
  assert.strictEqual(parseCIDR('1.2.3.4/33'), null);
  assert.strictEqual(parseCIDR('1.2.3.4'), null);
});

test('구역 판별: 4구역 각각', () => {
  const t = defaultTopology();
  assert.strictEqual(zoneOf(ip('172.16.10.10'), t), 'DMZ');
  assert.strictEqual(zoneOf(ip('10.10.2.10'), t), '내부망');
  assert.strictEqual(zoneOf(ip('10.20.1.20'), t), '개발·운영 서버망');
  assert.strictEqual(zoneOf(ip('203.0.113.10'), t), '인터넷');
});

test('구역 판별: 사설 구역 경계 밖은 인터넷', () => {
  assert.strictEqual(zoneOf(ip('172.16.11.1')), '인터넷');
  assert.strictEqual(zoneOf(ip('10.20.2.1')), '인터넷');
  assert.strictEqual(zoneOf(ip('10.11.0.1')), '인터넷');
});

test('기본 호스트는 모두 정확히 한 구역에 속한다', () => {
  const t = defaultTopology();
  const expect = { '웹서버': 'DMZ', '메일서버': 'DMZ', '관리자 PC': '내부망', 'DB 서버': '내부망',
    'SIEM': '내부망', '운영 서버': '개발·운영 서버망', '개발 서버': '개발·운영 서버망', '외부 사용자': '인터넷' };
  for (const h of t.hosts) assert.strictEqual(zoneOf(ip(h.ip), t), expect[h.name], h.name);
});
