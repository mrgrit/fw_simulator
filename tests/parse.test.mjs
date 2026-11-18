import assert from 'assert';
import { test } from './helper.mjs';
import { parseIPv4 } from '../src/core/topology.js';
import { parseAddress, addressMatches, parseService, serviceMatches, formatService, ERR_ADDR, ERR_SERVICE } from '../src/core/parse.js';

const ip = s => parseIPv4(s);

test('주소: Any (대소문자 무관)', () => {
  assert.ok(parseAddress('Any').value.any);
  assert.ok(parseAddress(' any ').value.any);
});

test('주소: 구역 이름 (앞뒤 공백은 무시)', () => {
  const r = parseAddress(' DMZ ');
  assert.ok(r.ok);
  assert.deepStrictEqual(r.value.zones, ['DMZ']);
  assert.ok(addressMatches(r.value, ip('172.16.10.99')));
  assert.ok(!addressMatches(r.value, ip('10.10.1.1')));
});

test('주소: 주소 그룹 (호스트·구역 혼합)', () => {
  const dev = parseAddress('개발·운영 서버').value;
  assert.ok(addressMatches(dev, ip('10.20.1.10')));
  assert.ok(addressMatches(dev, ip('10.20.1.20')));
  assert.ok(!addressMatches(dev, ip('10.20.1.30')));   // 같은 구역이어도 그룹 구성원이 아니면 불일치
  const mixed = parseAddress('내부 장비·DMZ').value;
  assert.ok(addressMatches(mixed, ip('10.10.9.9')));   // 구역 전체
  assert.ok(addressMatches(mixed, ip('172.16.10.10')));
  assert.ok(!addressMatches(mixed, ip('10.20.1.20')));
});

test('주소: 외부망 그룹 = 인터넷 구역', () => {
  const ext = parseAddress('외부망').value;
  assert.ok(addressMatches(ext, ip('203.0.113.10')));
  assert.ok(!addressMatches(ext, ip('172.16.10.10')));
});

test('주소: 단일 IP', () => {
  const r = parseAddress('10.10.1.10');
  assert.ok(r.ok);
  assert.ok(addressMatches(r.value, ip('10.10.1.10')));
  assert.ok(!addressMatches(r.value, ip('10.10.1.11')));
});

test('주소 오류: "알 수 없는 주소"', () => {
  for (const bad of ['', '   ', '없는구역', '300.1.1.1', '1.2.3', '웹서버', undefined, null, 42]) {
    const r = parseAddress(bad);
    assert.ok(!r.ok, String(bad));
    assert.strictEqual(r.error, ERR_ADDR);
  }
});

test('서비스: Any', () => {
  const r = parseService('Any');
  assert.ok(r.ok && r.value.any);
  assert.ok(serviceMatches(r.value, 'UDP', 53));
});

test('서비스: "TCP 80, 443" 은 프로토콜을 이어받는다', () => {
  const r = parseService('TCP 80, 443');
  assert.ok(r.ok);
  assert.deepStrictEqual(r.value.ranges.TCP, [[80, 80], [443, 443]]);
  assert.deepStrictEqual(r.value.ranges.UDP, []);
  assert.ok(serviceMatches(r.value, 'TCP', 443));
  assert.ok(!serviceMatches(r.value, 'UDP', 443));
  assert.ok(!serviceMatches(r.value, 'TCP', 8080));
});

test('서비스: 혼합 프로토콜 "UDP 514, TCP 9200"', () => {
  const r = parseService('UDP 514, TCP 9200');
  assert.ok(r.ok);
  assert.ok(serviceMatches(r.value, 'UDP', 514));
  assert.ok(serviceMatches(r.value, 'TCP', 9200));
  assert.ok(!serviceMatches(r.value, 'TCP', 514));
});

test('서비스: 범위와 병합, 슬래시 표기, 소문자', () => {
  assert.deepStrictEqual(parseService('TCP 100-200, 150-300, 301').value.ranges.TCP, [[100, 301]]);
  assert.deepStrictEqual(parseService('tcp/22').value.ranges.TCP, [[22, 22]]);
  const r = parseService('TCP 8000-8080');
  assert.ok(serviceMatches(r.value, 'TCP', 8000) && serviceMatches(r.value, 'TCP', 8080));
  assert.ok(!serviceMatches(r.value, 'TCP', 7999) && !serviceMatches(r.value, 'TCP', 8081));
});

test('서비스: 표준 형식으로 다시 출력', () => {
  assert.strictEqual(parseService('tcp 443,80').value.text, 'TCP 80, 443');
  assert.strictEqual(formatService(parseService('UDP 514, TCP 9200').value), 'TCP 9200, UDP 514');
});

test('서비스 오류: "서비스 형식 오류"', () => {
  const bads = ['', '  ', '80', 'TCP', 'TCP abc', 'TCP 0', 'TCP 65536', 'TCP 200-100', 'ICMP 1', 'TCP 80,',
    'TCP 80 443', 'TCP -80', 'TCP 80-', 'FTP 21', ',TCP 80', undefined, null, 80];
  for (const bad of bads) {
    const r = parseService(bad);
    assert.ok(!r.ok, String(bad));
    assert.strictEqual(r.error, ERR_SERVICE, String(bad));
  }
});
