// 정책 점검 (SPEC 2-2, 2-3, 2-4, 2-6). 공용 covers(A,B) 위에 섀도잉·중복·기본 거부·syslog 검사를 올린다.
// rules 는 matcher.compileRules 의 결과(번호 오름차순, 해석 완료)를 받는다.
import { defaultTopology, parseIPv4, zoneOf, findHost } from './topology.js';

export const WARN_NO_DEFAULT_DENY = '마지막 Any-Any 차단(기본 거부) 규칙이 없습니다';
export const SIEM_GROUP = '보안관제(SIEM)';
export const SYSLOG_PORT = 514;

// ---------- covers(A, B): A 가 B 의 범위를 완전히 덮는가 ----------

// 주소: A 가 Any 면 참. B 가 Any 이고 A 가 Any 가 아니면 거짓.
// 그 외에는 B 의 구역이 모두 A 의 구역에 있고, B 의 각 IP 가 A 의 IP 이거나 A 의 구역에 속해야 참.
export function addressCovers(a, b, topo) {
  if (a.any) return true;
  if (b.any) return false;
  if (b.zones.length === 0 && b.ips.length === 0) return false; // 비어 있는 주소는 판단 대상에서 제외
  for (const z of b.zones) {
    if (a.zones.indexOf(z) === -1) return false;
  }
  for (const ip of b.ips) {
    if (a.ips.indexOf(ip) === -1 && a.zones.indexOf(zoneOf(ip, topo)) === -1) return false;
  }
  return true;
}

// 서비스: A 가 Any 면 참. B 가 Any 이고 A 가 Any 가 아니면 거짓.
// 그 외에는 B 의 각 프로토콜 포트 범위가 A 의 같은 프로토콜 범위에 모두 포함되어야 참.
// (A 의 범위는 parseService 에서 이미 병합되어 있으므로 한 구간 안에 들어가면 된다.)
export function serviceCovers(a, b) {
  if (a.any) return true;
  if (b.any) return false;
  let any = false;
  for (const proto of ['TCP', 'UDP']) {
    for (const r of b.ranges[proto]) {
      any = true;
      if (!a.ranges[proto].some(x => x[0] <= r[0] && r[1] <= x[1])) return false;
    }
  }
  return any;
}

// 규칙 i 가 규칙 j 를 완전히 덮는가 (출발지·목적지·서비스 모두)
export function ruleCovers(i, j, topo) {
  return addressCovers(i.srcV, j.srcV, topo) && addressCovers(i.dstV, j.dstV, topo) && serviceCovers(i.svcV, j.svcV);
}

// ---------- 개별 검사 ----------

// 2-2 기본 거부: 마지막 규칙이 Any-Any-Any 차단이어야 한다.
export function checkDefaultDeny(rules) {
  const last = rules[rules.length - 1];
  const ok = last && last.srcV.any && last.dstV.any && last.svcV.any && last.action === 'deny';
  return ok ? [] : [{ type: 'no-default-deny', no: last ? last.no : null, message: WARN_NO_DEFAULT_DENY }];
}

// 2-3 섀도잉 / 2-4 중복
// 아래 규칙 j 에 대해 위 규칙 i(i<j) 가 j 를 완전히 덮을 때,
//   동작이 다르면 섀도잉(j 는 절대 적용되지 않음), 같으면 중복. 각각 가장 먼저 찾은 i 를 보고한다.
export function checkShadowingAndRedundancy(rules, topo) {
  const out = [];
  for (let jx = 0; jx < rules.length; jx++) {
    const j = rules[jx];
    let shadow = null;
    let dup = null;
    for (let ix = 0; ix < jx; ix++) {
      const i = rules[ix];
      if (!ruleCovers(i, j, topo)) continue;
      if (i.action !== j.action) { if (!shadow) shadow = i; }
      else if (!dup) dup = i;
    }
    if (shadow) {
      out.push({ type: 'shadowing', no: j.no, by: shadow.no,
        message: `규칙 ${j.no} 는 규칙 ${shadow.no} 에 가려져 절대 적용되지 않습니다(섀도잉)` });
    }
    if (dup) {
      out.push({ type: 'redundancy', no: j.no, by: dup.no,
        message: `규칙 ${j.no} 는 규칙 ${dup.no} 와 중복입니다(같은 트래픽·같은 동작)` });
    }
  }
  return out;
}

// 2-6 syslog 표준 포트: 로그 수집 규칙의 UDP 서비스 포트에 514 가 없으면 경고.
// 로그 수집 규칙 = 목적지가 '보안관제(SIEM)' 그룹이거나 SIEM 호스트 IP, 또는 목적에 'syslog'/'로그' 포함.
// 허용(allow) 규칙만 대상으로 하고, UDP 포트가 하나도 없는 규칙(예: TCP 9200 만)은 검사하지 않는다.
export function checkSyslogPort(rules, topo) {
  const t = topo || defaultTopology();
  const siem = findHost('SIEM', t);
  const siemIp = siem ? parseIPv4(siem.ip) : null;
  const out = [];
  for (const r of rules) {
    if (r.action !== 'allow') continue;
    const toSiem = r.dstV.text === SIEM_GROUP || (!r.dstV.any && siemIp !== null && r.dstV.ips.indexOf(siemIp) !== -1);
    const byPurpose = /syslog|로그/i.test(r.purpose || '');
    if (!toSiem && !byPurpose) continue;
    if (r.svcV.any) continue;                 // Any 는 514 를 포함한다
    const udp = r.svcV.ranges.UDP;
    if (udp.length === 0) continue;
    if (udp.some(x => x[0] <= SYSLOG_PORT && SYSLOG_PORT <= x[1])) continue;
    const ports = udp.map(x => (x[0] === x[1] ? String(x[0]) : x[0] + '-' + x[1])).join(', ');
    out.push({ type: 'syslog-port', no: r.no,
      message: `규칙 ${r.no}: syslog 표준 포트가 아님 (UDP ${ports} → 표준 포트는 UDP ${SYSLOG_PORT})` });
  }
  return out;
}

// 정책 점검 전체. 반환: [{ type, no, by?, message }]  (규칙 번호순, 같은 규칙이면 검사 순서)
export function analyze(rules, topo) {
  const all = [].concat(
    checkDefaultDeny(rules),
    checkShadowingAndRedundancy(rules, topo),
    checkSyslogPort(rules, topo)
  );
  return all;
}
