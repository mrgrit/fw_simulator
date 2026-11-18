// 화면에 보여 줄 문구를 만드는 순수 함수들 (DOM 비의존 → 테스트 가능).
import { defaultTopology, parseIPv4, zoneOf } from '../core/topology.js';

export const ACTION_LABEL = { allow: '허용', deny: '차단' };
export const FIELD_LABELS = { src: '출발지', dst: '목적지', service: '서비스', action: '동작', purpose: '목적', position: '위치', no: '규칙 번호' };
export const TYPE_LABEL = { shadowing: '섀도잉', redundancy: '중복', 'no-default-deny': '기본 거부 없음', 'syslog-port': 'syslog 포트' };
export const TYPE_REF = { shadowing: 'SPEC 2-3', redundancy: 'SPEC 2-4', 'no-default-deny': 'SPEC 2-2', 'syslog-port': 'SPEC 2-6' };
export const CHANGE_LABEL = { add: '추가', update: '수정', delete: '삭제', move: '이동' };

// 교수자 함정과 기본 정책표 각 행을 한 번에 시험해 보는 예제 패킷. expect 는 기본 정책표 기준 기대 결과.
export const SCENARIOS = [
  { label: '함정 2: 개발 서버 → 인터넷 HTTPS', src: '10.20.1.20', dst: '203.0.113.10', proto: 'TCP', port: 443, expect: { action: 'deny', no: 5 } },
  { label: '외부 사용자 → 웹서버 HTTPS', src: '203.0.113.10', dst: '172.16.10.10', proto: 'TCP', port: 443, expect: { action: 'allow', no: 1 } },
  { label: '웹서버 → DB 서버 MySQL', src: '172.16.10.10', dst: '10.10.2.10', proto: 'TCP', port: 3306, expect: { action: 'allow', no: 2 } },
  { label: '메일서버 → DB 서버 MySQL (지정 IP 아님)', src: '172.16.10.20', dst: '10.10.2.10', proto: 'TCP', port: 3306, expect: { action: 'deny', no: 5 } },
  { label: '관리자 PC → 개발 서버 SSH', src: '10.10.1.10', dst: '10.20.1.20', proto: 'TCP', port: 22, expect: { action: 'allow', no: 3 } },
  { label: '개발 서버 → 관리자 PC SSH (역방향)', src: '10.20.1.20', dst: '10.10.1.10', proto: 'TCP', port: 22, expect: { action: 'deny', no: 5 } },
  { label: '웹서버 → SIEM syslog', src: '172.16.10.10', dst: '10.10.3.10', proto: 'UDP', port: 514, expect: { action: 'allow', no: 4 } },
];

export function ruleSummary(r) {
  return `${r.src} → ${r.dst} ${r.service} ${ACTION_LABEL[r.action] || r.action}`;
}

// "이름 (IP)" 형태. 호스트 목록에 없으면 IP 만.
export function hostLabel(ip, topo) {
  const t = topo || defaultTopology();
  const h = t.hosts.find(x => x.ip === ip);
  return h ? `${h.name} (${ip})` : ip;
}

const mark = b => (b ? '✓' : '✗');
export function traceLine(t) {
  return `${t.no}번  출발지 ${mark(t.src)}  목적지 ${mark(t.dst)}  서비스 ${mark(t.svc)}  → ${t.matched ? '일치' : '불일치'}`;
}

// 판정 결과를 화면용으로 풀어 쓴다. input 은 사용자가 입력한 문자열 { src, dst, proto, port }.
export function describeJudge(result, input, topo) {
  const verdict = ACTION_LABEL[result.action];
  const headline = result.matched
    ? `${verdict} — 규칙 ${result.matched.no} 에 일치`
    : `${verdict} (암묵적 차단) — 일치하는 규칙 없음`;
  return {
    action: result.action,
    headline,
    packetText: `${hostLabel(input.src, topo)} → ${hostLabel(input.dst, topo)}  ${String(input.proto).toUpperCase()}/${input.port}`,
    pathText: `${result.srcZone} → 방화벽 → ${result.dstZone}`,
    traceLines: result.trace.map(traceLine),
    stoppedNote: result.matched ? `규칙 ${result.matched.no} 에서 멈춤 — 아래 규칙은 보지 않습니다 (first-match)` : '',
    warnings: result.warnings.slice(),
  };
}

// 점검 결과 → { 규칙번호: [finding...] } (표의 배지용)
export function findingsByRule(findings) {
  const map = {};
  (findings || []).forEach(f => {
    if (f.no === null || f.no === undefined) return;
    (map[f.no] = map[f.no] || []).push(f);
  });
  return map;
}

// 수정 이력의 변경 항목 [{field, before, after}]
export function historyDiff(e) {
  if (e.type === 'move') return [{ field: '번호', before: `${e.before.no}번`, after: `${e.after.no}번` }];
  if (e.type === 'add') return [{ field: '규칙', before: '(없음)', after: ruleSummary(e.after) }];
  if (e.type === 'delete') return [{ field: '규칙', before: ruleSummary(e.before), after: '(삭제됨)' }];
  const out = [];
  ['src', 'dst', 'service', 'action', 'purpose'].forEach(k => {
    if (e.before[k] !== e.after[k]) {
      const f = v => (k === 'action' ? ACTION_LABEL[v] || v : (v === '' ? '(비어 있음)' : v));
      out.push({ field: FIELD_LABELS[k], before: f(e.before[k]), after: f(e.after[k]) });
    }
  });
  return out;
}

export function summarizeEntry(e) {
  if (e.type === 'add') return `규칙 ${e.ruleNo} 추가: ${ruleSummary(e.after)}`;
  if (e.type === 'delete') return `규칙 ${e.ruleNo} 삭제: ${ruleSummary(e.before)}`;
  if (e.type === 'move') return `규칙 ${e.before.no}번 → ${e.after.no}번으로 이동 (${ruleSummary(e.after)})`;
  return `규칙 ${e.ruleNo} 수정: ` + historyDiff(e).map(d => `${d.field} ${d.before} → ${d.after}`).join('; ');
}

// ISO8601(UTC) 시각을 "YYYY-MM-DD HH:MM:SS" 로 (시간대 변환 없이 표시, 원문은 title 로 보존)
export function shortTime(iso) {
  return String(iso).replace('T', ' ').replace(/(\.\d+)?Z$/, '');
}
