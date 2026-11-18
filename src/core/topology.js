// 토폴로지: 구역 4개, 호스트, 주소 그룹, IPv4/CIDR 유틸. (PLAN 1절, SPEC 2절 서두)
// DOM·I/O 에 의존하지 않는 순수 모듈.

export const INTERNET = '인터넷';

export const ZONES = [
  { name: INTERNET }, // CIDR 없음: 어느 사설 구역에도 속하지 않는 모든 IP
  { name: 'DMZ', cidr: '172.16.10.0/24' },
  { name: '내부망', cidr: '10.10.0.0/16' },
  { name: '개발·운영 서버망', cidr: '10.20.1.0/24' },
];

export const HOSTS = [
  { name: '웹서버', ip: '172.16.10.10' },
  { name: '메일서버', ip: '172.16.10.20' },
  { name: '관리자 PC', ip: '10.10.1.10' },
  { name: 'DB 서버', ip: '10.10.2.10' },
  { name: 'SIEM', ip: '10.10.3.10' },
  { name: '운영 서버', ip: '10.20.1.10' },
  { name: '개발 서버', ip: '10.20.1.20' },
  { name: '외부 사용자', ip: '203.0.113.10' },
];

// 그룹 구성원: { zone: 구역이름 } 또는 { host: 호스트이름 }
export const GROUPS = [
  { name: '외부망', members: [{ zone: INTERNET }] },
  { name: 'DMZ 웹서버', members: [{ host: '웹서버' }] },
  { name: '내부망 DB 서버', members: [{ host: 'DB 서버' }] },
  { name: '내부망 관리자 PC', members: [{ host: '관리자 PC' }] },
  { name: '개발·운영 서버', members: [{ host: '운영 서버' }, { host: '개발 서버' }] },
  { name: '보안관제(SIEM)', members: [{ host: 'SIEM' }] },
  { name: '내부 장비·DMZ', members: [{ zone: '내부망' }, { zone: 'DMZ' }] },
];

export function defaultTopology() {
  return { zones: ZONES, hosts: HOSTS, groups: GROUPS };
}

// ---------- IPv4 ----------

// "a.b.c.d" 를 32비트 부호 없는 정수로. 형식이 틀리면 null.
// 각 옥텟은 0~255 의 10진수이고 앞자리 0(01 등)은 거부한다.
export function parseIPv4(str) {
  if (typeof str !== 'string') return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(str.trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const s = m[i];
    if (s.length > 1 && s[0] === '0') return null;
    const v = Number(s);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function formatIPv4(n) {
  return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
}

// "a.b.c.d/len" → { base, size } (base 는 네트워크 주소). 틀리면 null.
export function parseCIDR(str) {
  const m = /^([^/]+)\/(\d{1,2})$/.exec(String(str).trim());
  if (!m) return null;
  const ip = parseIPv4(m[1]);
  const len = Number(m[2]);
  if (ip === null || len > 32) return null;
  const size = Math.pow(2, 32 - len);
  return { base: Math.floor(ip / size) * size, size };
}

export function cidrContains(cidr, ip) {
  const c = typeof cidr === 'string' ? parseCIDR(cidr) : cidr;
  return c !== null && ip >= c.base && ip < c.base + c.size;
}

// IP(정수) 가 속한 구역 이름. 사설 구역에 없으면 '인터넷'.
export function zoneOf(ip, topo) {
  const t = topo || defaultTopology();
  for (const z of t.zones) {
    if (z.cidr && cidrContains(z.cidr, ip)) return z.name;
  }
  return INTERNET;
}

export function findHost(name, topo) {
  const t = topo || defaultTopology();
  return t.hosts.find(h => h.name === name) || null;
}
