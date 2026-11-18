// 기본 정책표: 실무 기준 NW 보안 구축 문2 과제2의 5행 (SPEC 1-2, 교재 10장 표)
// 규칙 형식: { no, src, dst, service, action: 'allow'|'deny', purpose }
export function defaultRules() {
  return [
    { no: 1, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80, 443', action: 'allow', purpose: '외부 사용자 서비스 제공' },
    { no: 2, src: 'DMZ 웹서버', dst: '내부망 DB 서버', service: 'TCP 1433, 3306', action: 'allow', purpose: '웹서비스용 DB 연동(지정 IP 한정)' },
    { no: 3, src: '내부망 관리자 PC', dst: '개발·운영 서버', service: 'TCP 22', action: 'allow', purpose: '내부 특정 IP만 관리 접근' },
    { no: 4, src: '내부 장비·DMZ', dst: '보안관제(SIEM)', service: 'UDP 514, TCP 9200', action: 'allow', purpose: '로그 중앙 수집' },
    { no: 5, src: 'Any', dst: 'Any', service: 'Any', action: 'deny', purpose: '미허용 트래픽·역방향 트래픽 전면 차단' },
  ];
}
