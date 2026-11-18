// 입력 파싱·검증 (SPEC 2-7). 실패 시 throw 하지 않고 { ok:false, error } 를 돌려준다.
import { defaultTopology, parseIPv4, formatIPv4, findHost, zoneOf } from './topology.js';

export const ERR_ADDR = '알 수 없는 주소';
export const ERR_SERVICE = '서비스 형식 오류';

// ---------- 주소 ----------
// 허용: Any | 구역 이름 | 주소 그룹 이름 | 단일 IPv4
// 결과 value = { any, zones:[구역이름], ips:[정수], text }
//   zones 는 구역 전체, ips 는 개별 호스트 주소.
export function parseAddress(text, topo) {
  const t = topo || defaultTopology();
  const s = typeof text === 'string' ? text.trim() : '';
  if (s === '') return { ok: false, error: ERR_ADDR };

  if (s.toLowerCase() === 'any') {
    return { ok: true, value: { any: true, zones: [], ips: [], text: 'Any' } };
  }
  if (t.zones.some(z => z.name === s)) {
    return { ok: true, value: { any: false, zones: [s], ips: [], text: s } };
  }
  const group = t.groups.find(g => g.name === s);
  if (group) {
    const zones = [];
    const ips = [];
    for (const m of group.members) {
      if (m.zone) zones.push(m.zone);
      else {
        const h = findHost(m.host, t);
        if (h) ips.push(parseIPv4(h.ip));
      }
    }
    return { ok: true, value: { any: false, zones, ips, text: s } };
  }
  const ip = parseIPv4(s);
  if (ip !== null) {
    return { ok: true, value: { any: false, zones: [], ips: [ip], text: formatIPv4(ip) } };
  }
  return { ok: false, error: ERR_ADDR };
}

// IP(정수) 가 주소 값에 해당하는지.
export function addressMatches(addr, ip, topo) {
  if (addr.any) return true;
  if (addr.ips.indexOf(ip) !== -1) return true;
  return addr.zones.indexOf(zoneOf(ip, topo)) !== -1;
}

// ---------- 서비스 ----------
// 문법 예: "Any", "TCP 80, 443", "UDP 514, TCP 9200", "TCP 8000-8080", "TCP/22"
// 결과 value = { any, ranges: { TCP:[[from,to],...], UDP:[...] }, text }
// 프로토콜 단어는 다음 프로토콜이 나올 때까지 뒤따르는 포트에 적용된다.
export function parseService(text) {
  const s = typeof text === 'string' ? text.trim() : '';
  if (s === '') return { ok: false, error: ERR_SERVICE };
  if (s.toLowerCase() === 'any') {
    return { ok: true, value: { any: true, ranges: { TCP: [], UDP: [] }, text: 'Any' } };
  }

  const ranges = { TCP: [], UDP: [] };
  let proto = null;
  const pieces = s.replace(/\//g, ' ').split(',');
  for (const piece of pieces) {
    const words = piece.trim().split(/\s+/).filter(w => w !== '');
    if (words.length === 0) return { ok: false, error: ERR_SERVICE };
    let portWord;
    const head = words[0].toUpperCase();
    if (head === 'TCP' || head === 'UDP') {
      proto = head;
      if (words.length !== 2) return { ok: false, error: ERR_SERVICE };
      portWord = words[1];
    } else {
      if (proto === null || words.length !== 1) return { ok: false, error: ERR_SERVICE };
      portWord = words[0];
    }
    const r = parsePortRange(portWord);
    if (!r) return { ok: false, error: ERR_SERVICE };
    ranges[proto].push(r);
  }
  ranges.TCP = mergeRanges(ranges.TCP);
  ranges.UDP = mergeRanges(ranges.UDP);
  return { ok: true, value: { any: false, ranges, text: formatService({ any: false, ranges }) } };
}

function parsePortRange(w) {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(w);
  if (!m) return null;
  const from = Number(m[1]);
  const to = m[2] === undefined ? from : Number(m[2]);
  if (from < 1 || to > 65535 || from > to) return null;
  return [from, to];
}

// 겹치거나 맞닿은 구간을 합치고 정렬한다.
export function mergeRanges(list) {
  const sorted = list.slice().sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push([r[0], r[1]]);
  }
  return out;
}

export function formatService(v) {
  if (v.any) return 'Any';
  const parts = [];
  for (const p of ['TCP', 'UDP']) {
    if (v.ranges[p].length === 0) continue;
    const ports = v.ranges[p].map(r => (r[0] === r[1] ? String(r[0]) : r[0] + '-' + r[1]));
    parts.push(p + ' ' + ports.join(', '));
  }
  return parts.join(', ');
}

// 패킷의 프로토콜·포트가 서비스 값에 해당하는지.
export function serviceMatches(svc, proto, port) {
  if (svc.any) return true;
  const list = svc.ranges[proto];
  if (!list) return false;
  return list.some(r => port >= r[0] && port <= r[1]);
}
