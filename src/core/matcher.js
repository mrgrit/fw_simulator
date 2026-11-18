// 패킷 판정 = first-match (SPEC 2-1). 위(번호 오름차순)에서부터 비교해
// 출발지·목적지·프로토콜·포트가 모두 일치하는 '첫 규칙 하나'의 동작만 적용하고 즉시 멈춘다.
import { defaultTopology, parseIPv4, zoneOf } from './topology.js';
import { parseAddress, parseService, addressMatches, serviceMatches, ERR_ADDR, ERR_SERVICE } from './parse.js';

export const WARN_NO_MATCH = '일치 규칙 없음 — 기본 거부 규칙 필요';

// 원본 규칙 1개를 해석한다. 성공 시 { ok:true, rule }, 실패 시 { ok:false, errors:[{field,error}] }
// rule = 원본 필드 + srcV, dstV, svcV (해석된 값)
export function compileRule(raw, topo) {
  const errors = [];
  const src = parseAddress(raw.src, topo);
  const dst = parseAddress(raw.dst, topo);
  const svc = parseService(raw.service);
  if (!src.ok) errors.push({ field: 'src', error: src.error });
  if (!dst.ok) errors.push({ field: 'dst', error: dst.error });
  if (!svc.ok) errors.push({ field: 'service', error: svc.error });
  if (raw.action !== 'allow' && raw.action !== 'deny') errors.push({ field: 'action', error: '동작은 allow 또는 deny' });
  if (errors.length) return { ok: false, errors };
  return { ok: true, rule: Object.assign({}, raw, { srcV: src.value, dstV: dst.value, svcV: svc.value }) };
}

// 규칙 목록 전체를 해석한다. 잘못된 규칙은 rules 에서 빠지고 errors 로 보고된다.
// rules 는 번호 오름차순(위→아래)으로 정렬되어 반환된다.
export function compileRules(rawRules, topo) {
  const rules = [];
  const errors = [];
  for (const raw of rawRules) {
    const r = compileRule(raw, topo);
    if (r.ok) rules.push(r.rule);
    else r.errors.forEach(e => errors.push({ no: raw.no, field: e.field, error: e.error }));
  }
  rules.sort((a, b) => a.no - b.no);
  return { rules, errors };
}

// 화면 입력 형태 { src, dst, proto, port } 를 검증해 판정용 패킷으로 만든다.
export function parsePacket(input) {
  const srcIp = parseIPv4(input.src);
  const dstIp = parseIPv4(input.dst);
  if (srcIp === null || dstIp === null) return { ok: false, error: ERR_ADDR };
  const proto = String(input.proto || '').toUpperCase();
  const port = typeof input.port === 'number' ? input.port : (/^\d{1,5}$/.test(String(input.port).trim()) ? Number(input.port) : NaN);
  if ((proto !== 'TCP' && proto !== 'UDP') || !(port >= 1 && port <= 65535) || Math.floor(port) !== port) {
    return { ok: false, error: ERR_SERVICE };
  }
  return { ok: true, packet: { srcIp, dstIp, proto, port } };
}

// 규칙 하나가 패킷에 맞는지 (출발지·목적지·서비스 각각의 결과를 함께 돌려준다)
export function ruleMatches(rule, packet, topo) {
  const src = addressMatches(rule.srcV, packet.srcIp, topo);
  const dst = addressMatches(rule.dstV, packet.dstIp, topo);
  const svc = serviceMatches(rule.svcV, packet.proto, packet.port);
  return { src, dst, svc, all: src && dst && svc };
}

// 판정. rules 는 compileRules 의 결과(정렬됨)를 받는다.
// 반환: { action, matched(규칙|null), implicit, warnings[], srcZone, dstZone, trace[] }
//   trace 는 실제로 비교한 규칙들(일치 규칙까지)이며, 화면에서 '길찾기' 과정을 보여줄 때 쓴다.
export function evaluate(rules, packet, topo) {
  const t = topo || defaultTopology();
  const result = {
    action: 'deny',
    matched: null,
    implicit: false,
    warnings: [],
    srcZone: zoneOf(packet.srcIp, t),
    dstZone: zoneOf(packet.dstIp, t),
    trace: [],
  };
  for (const rule of rules) {
    const m = ruleMatches(rule, packet, t);
    result.trace.push({ no: rule.no, src: m.src, dst: m.dst, svc: m.svc, matched: m.all });
    if (m.all) {            // 첫 일치 규칙에서 즉시 멈춘다 (이후 규칙은 보지 않는다)
      result.action = rule.action;
      result.matched = rule;
      return result;
    }
  }
  result.implicit = true;   // 일치 규칙 없음 → 암묵적 차단
  result.warnings.push(WARN_NO_MATCH);
  return result;
}
