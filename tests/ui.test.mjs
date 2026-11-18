import assert from 'assert';
import { test } from './helper.mjs';
import { makeDoc, memStorage, fire, findAll } from './fakedom.mjs';
import { mount } from '../src/ui/main.js';
import { STORAGE_KEY } from '../src/ui/storage.js';

function boot(storage, extra) {
  const doc = makeDoc();
  let tick = 0;
  const downloads = [];
  const app = mount(doc, Object.assign({
    storage: storage || memStorage(),
    now: () => new Date(Date.UTC(2026, 10, 18, 0, 0, tick++)).toISOString(),
    confirm: () => true,
    download: (name, text) => downloads.push({ name, text }),
  }, extra || {}));
  const $ = id => doc.getElementById(id);
  const rows = () => $('rules').children;
  const cells = tr => tr.children.map(td => td.textContent);
  const classes = id => ($(id).className || '').split(' ').filter(Boolean);
  const type = (id, v) => { $(id).value = v; };
  const submitRule = () => fire($('rule-form'), 'submit');
  return { doc, app, $, rows, cells, classes, type, submitRule, downloads };
}
const T = n => n.textContent;
const STORE_HAS = s => typeof s.d[STORAGE_KEY] === 'string' && s.d[STORAGE_KEY].indexOf('"history"') !== -1;
const addAnyAllowAtTop = ui => {
  ui.type('f-src', 'Any'); ui.type('f-dst', 'Any'); ui.type('f-service', 'Any'); ui.type('f-action', 'allow'); ui.type('f-position', '1');
  ui.submitRule();
};

test('UI: 처음 화면 — 기본 5행, 4구역, 메시지 없음', () => {
  const ui = boot();
  assert.strictEqual(ui.rows().length, 5);
  assert.deepStrictEqual(ui.cells(ui.rows()[0]).slice(0, 5), ['1', '외부망', 'DMZ 웹서버', 'TCP 80, 443', '허용']);
  assert.deepStrictEqual(ui.cells(ui.rows()[4]).slice(0, 5), ['5', 'Any', 'Any', 'Any', '차단']);
  const zones = findAll(ui.doc.root, n => (n.className || '').split(' ').indexOf('zone') !== -1);
  assert.strictEqual(zones.length, 4);
  assert.ok(T(zones[0]).indexOf('인터넷') !== -1 && T(zones[1]).indexOf('DMZ') !== -1);
  assert.strictEqual(ui.$('msg').hidden, true);
  assert.ok(T(ui.$('result')).indexOf('길찾기') !== -1);
  assert.strictEqual(ui.$('panel-packet').hidden, false);
  assert.strictEqual(ui.$('panel-check').hidden, true);
});

test('UI: 함정 2 예제 — 5번 규칙 차단, 비교한 규칙 표시, 구역 강조', () => {
  const ui = boot();
  ui.$('scenario-0').click();
  assert.ok(T(ui.$('result')).indexOf('차단 — 규칙 5 에 일치') !== -1);
  assert.deepStrictEqual([1, 2, 3, 4].map(n => ui.classes('rule-' + n)), [['miss'], ['miss'], ['miss'], ['miss']]);
  assert.deepStrictEqual(ui.classes('rule-5'), ['hit']);
  const zones = findAll(ui.doc.root, n => (n.className || '').split(' ').indexOf('zone') !== -1);
  const src = zones.filter(z => z.className.indexOf('src') !== -1).map(z => T(z).slice(0, 8));
  const dst = zones.filter(z => z.className.indexOf('dst') !== -1).map(z => T(z).slice(0, 3));
  assert.strictEqual(src.length, 1); assert.ok(src[0].indexOf('개발·운영') === 0);
  assert.deepStrictEqual(dst, ['인터넷']);
  const path = findAll(ui.doc.root, n => (n.className || '').indexOf('pathline') !== -1)[0];
  assert.strictEqual(T(path), '개발·운영 서버망 → 방화벽 → 인터넷 : 차단 — 규칙 5 에 일치');
  assert.ok(T(ui.$('result')).indexOf('first-match') !== -1);
});

test('UI: 패킷 직접 입력 — 허용 1번은 첫 규칙에서 멈춤 / 잘못된 입력은 오류 문구', () => {
  const ui = boot();
  ui.type('p-src', '203.0.113.10'); ui.type('p-dst', '172.16.10.10'); ui.type('p-proto', 'TCP'); ui.type('p-port', '80');
  fire(ui.$('packet-form'), 'submit');
  assert.ok(T(ui.$('result')).indexOf('허용 — 규칙 1 에 일치') !== -1);
  assert.deepStrictEqual(ui.classes('rule-1'), ['hit']);
  assert.deepStrictEqual(ui.classes('rule-2'), []);                 // 비교하지 않은 규칙은 표시 없음
  ui.type('p-src', '999.1.1.1');
  fire(ui.$('packet-form'), 'submit');
  assert.ok(T(ui.$('result')).indexOf('알 수 없는 주소') !== -1);
  ui.type('p-src', '10.10.1.10'); ui.type('p-port', '0');
  fire(ui.$('packet-form'), 'submit');
  assert.ok(T(ui.$('result')).indexOf('서비스 형식 오류') !== -1);
});

test('UI: 호스트 빠른 선택이 IP 입력칸을 채운다', () => {
  const ui = boot();
  const pick = ui.$('p-src-pick');
  pick.value = '172.16.10.10';
  fire(pick, 'change', { target: pick });
  assert.strictEqual(ui.$('p-src').value, '172.16.10.10');
});

test('UI: 정책 점검 — 기본 정책표는 경고 없음', () => {
  const ui = boot();
  ui.$('btn-check').click();
  assert.strictEqual(ui.$('panel-check').hidden, false);
  assert.ok(T(ui.$('check-result')).indexOf('경고 없음') !== -1);
});

test('UI: 규칙 추가(위치 1) → 함정 1 섀도잉 경고·배지, 판정 자동 갱신, 이력 기록, 저장', () => {
  const store = memStorage();
  const ui = boot(store);
  ui.$('scenario-0').click();                                        // 먼저 차단 판정
  addAnyAllowAtTop(ui);
  assert.strictEqual(ui.rows().length, 6);
  assert.deepStrictEqual(ui.cells(ui.rows()[0]).slice(0, 5), ['1', 'Any', 'Any', 'Any', '허용']);
  assert.ok(T(ui.$('msg')).indexOf('규칙 1번을 추가했습니다') !== -1);
  assert.ok(T(ui.$('result')).indexOf('허용 — 규칙 1 에 일치') !== -1);   // 같은 패킷이 이제 허용으로 자동 재판정
  ui.$('btn-check').click();
  assert.strictEqual(ui.$('panel-check').hidden, false);
  assert.ok(T(ui.$('check-result')).indexOf('규칙 6 는 규칙 1 에 가려져 절대 적용되지 않습니다(섀도잉)') !== -1);
  assert.ok(T(ui.$('rule-6')).indexOf('섀도잉') !== -1);
  assert.ok(T(ui.$('rule-2')).indexOf('중복') !== -1);                // 같은 허용 → 중복
  const f = findAll(ui.doc.root, n => (n.id || '').indexOf('finding-') === 0).find(n => T(n).indexOf('규칙 6 는 규칙 1') !== -1);
  fire(f, 'click');                                                  // 항목 클릭 → 관련 규칙 강조
  assert.ok(ui.classes('rule-6').indexOf('focus') !== -1 && ui.classes('rule-1').indexOf('focus') !== -1);
  ui.$('tab-history').click();
  assert.strictEqual(ui.$('panel-history').hidden, false);
  assert.ok(T(ui.$('history')).indexOf('규칙 1 추가: Any → Any Any 허용') !== -1);
  assert.ok(T(ui.$('history')).indexOf('관리자') !== -1);              // 기본 변경자
  assert.ok(STORE_HAS(store));
  assert.strictEqual(ui.$('f-src').value, '');                       // 폼은 비워짐
});

test('UI: 변경자 이름이 이력에 남는다', () => {
  const ui = boot();
  ui.type('by', '홍길동');
  ui.$('del-5').click();
  assert.strictEqual(ui.app.policy.getHistory()[0].by, '홍길동');
  ui.type('by', '   ');
  ui.$('del-4').click();
  assert.strictEqual(ui.app.policy.getHistory()[1].by, '관리자');
});

test('UI: 잘못된 규칙 입력 — 오류만 표시하고 표·이력은 그대로', () => {
  const ui = boot();
  ui.type('f-src', '없는곳'); ui.type('f-dst', 'DMZ'); ui.type('f-service', 'TCP x'); ui.type('f-action', 'allow');
  ui.submitRule();
  const errs = ui.$('form-err').children.map(T);
  assert.deepStrictEqual(errs, ['출발지: 알 수 없는 주소', '서비스: 서비스 형식 오류']);
  assert.strictEqual(ui.rows().length, 5);
  assert.strictEqual(ui.app.policy.getHistory().length, 0);
  assert.strictEqual(ui.$('f-src').value, '없는곳');                  // 입력은 유지(고쳐서 다시 제출)
  ui.type('f-src', 'Any'); ui.type('f-service', 'TCP 80'); ui.type('f-position', '9');
  ui.submitRule();
  assert.deepStrictEqual(ui.$('form-err').children.map(T), ['위치: 위치 범위 오류']);
});

test('UI: 수정 — 폼 채우기, 함정 3 syslog 경고, 이력에 수정 전·후', () => {
  const ui = boot();
  ui.$('edit-4').click();
  assert.strictEqual(ui.$('f-service').value, 'UDP 514, TCP 9200');
  assert.strictEqual(ui.$('f-submit').textContent, '저장');
  assert.strictEqual(ui.$('f-cancel').hidden, false);
  assert.strictEqual(ui.$('f-position').disabled, true);
  ui.type('f-service', 'UDP 513, TCP 9200');
  ui.submitRule();
  assert.strictEqual(ui.cells(ui.rows()[3])[3], 'UDP 513, TCP 9200');
  assert.strictEqual(ui.$('f-submit').textContent, '추가');
  ui.$('btn-check').click();
  assert.ok(T(ui.$('check-result')).indexOf('규칙 4: syslog 표준 포트가 아님 (UDP 513 → 표준 포트는 UDP 514)') !== -1);
  ui.$('edit-4').click();
  ui.type('f-service', 'UDP 514, TCP 9200');
  ui.submitRule();
  assert.ok(T(ui.$('check-result')).indexOf('경고 없음') !== -1);       // 점검 결과도 자동 갱신
  assert.strictEqual(ui.app.policy.getHistory().length, 2);
  ui.$('tab-history').click();
  assert.ok(T(ui.$('history')).indexOf('서비스 UDP 514, TCP 9200 → UDP 513, TCP 9200') !== -1);
});

test('UI: 수정 취소, 바뀐 것 없음', () => {
  const ui = boot();
  ui.$('edit-2').click();
  ui.$('f-cancel').click();
  assert.strictEqual(ui.$('f-src').value, '');
  assert.strictEqual(ui.$('f-submit').textContent, '추가');
  ui.$('edit-2').click();
  ui.submitRule();                                                   // 그대로 저장
  assert.ok(T(ui.$('msg')).indexOf('변경 사항이 없습니다') !== -1);
  assert.strictEqual(ui.app.policy.getHistory().length, 0);
});

test('UI: 이동 ▲▼ — 기본 거부를 위로 올리면 허용 규칙이 섀도잉', () => {
  const ui = boot();
  ui.$('up-1').click();                                              // 맨 위 ▲ 는 무시
  assert.strictEqual(ui.app.policy.getHistory().length, 0);
  ui.$('down-5').click();                                            // 맨 아래 ▼ 도 무시
  assert.strictEqual(ui.app.policy.getHistory().length, 0);
  for (let n = 5; n > 1; n--) ui.$('up-' + n).click();               // 5번을 1번 자리까지
  assert.strictEqual(ui.cells(ui.rows()[0])[4], '차단');
  assert.strictEqual(ui.app.policy.getHistory().length, 4);
  ui.$('btn-check').click();
  assert.ok(T(ui.$('check-result')).indexOf('가려져 절대 적용되지 않습니다(섀도잉)') !== -1);
});

test('UI: 삭제 — 확인 거부 시 그대로, 승인 시 삭제', () => {
  let answer = false;
  const ui = boot(null, { confirm: () => answer });
  ui.$('del-1').click();
  assert.strictEqual(ui.rows().length, 5);
  answer = true;
  ui.$('del-1').click();
  assert.strictEqual(ui.rows().length, 4);
  assert.strictEqual(ui.cells(ui.rows()[0])[1], 'DMZ 웹서버');
  assert.strictEqual(ui.app.policy.getHistory()[0].type, 'delete');
});

test('UI: 기본 거부를 지우면 점검 배너와 암묵적 차단 경고', () => {
  const ui = boot();
  ui.$('del-5').click();
  ui.$('btn-check').click();
  const banner = findAll(ui.doc.root, n => (n.className || '').indexOf('banner') !== -1)[0];
  assert.ok(T(banner).indexOf('마지막 Any-Any 차단(기본 거부) 규칙이 없습니다') !== -1);
  ui.$('scenario-0').click();
  assert.ok(T(ui.$('result')).indexOf('차단 (암묵적 차단) — 일치하는 규칙 없음') !== -1);
  assert.ok(T(ui.$('result')).indexOf('일치 규칙 없음 — 기본 거부 규칙 필요') !== -1);
});

test('UI: 새로 열어도 저장된 정책표와 이력이 복원된다', () => {
  const store = memStorage();
  const a = boot(store);
  addAnyAllowAtTop(a);
  a.$('del-6').click();
  const b = boot(store);
  assert.strictEqual(b.rows().length, 5);
  assert.strictEqual(b.cells(b.rows()[0])[1], 'Any');
  assert.strictEqual(b.app.policy.getHistory().length, 2);
  b.$('tab-history').click();
  assert.ok(T(b.$('history')).indexOf('총 2건') !== -1);
});

test('UI: 저장소가 막혀 있어도 동작하고 경고를 보여 준다', () => {
  const broken = { getItem() { throw new Error('x'); }, setItem() { throw new Error('x'); } };
  const ui = boot(broken);
  assert.strictEqual(ui.rows().length, 5);
  ui.$('del-5').click();
  assert.strictEqual(ui.rows().length, 4);
  assert.ok(T(ui.$('msg')).indexOf('저장소를 쓸 수 없어') !== -1);
});

test('UI: 초기화 — 확인하면 기본 5행·이력 삭제, 거부하면 유지', () => {
  let answer = true;
  const ui = boot(null, { confirm: () => answer });
  ui.$('del-5').click();
  assert.strictEqual(ui.rows().length, 4);
  answer = false;
  ui.$('btn-reset').click();
  assert.strictEqual(ui.rows().length, 4);                           // 거부하면 유지
  answer = true;
  ui.$('btn-reset').click();
  assert.strictEqual(ui.rows().length, 5);
  assert.strictEqual(ui.app.policy.getHistory().length, 0);
  assert.ok(T(ui.$('msg')).indexOf('초기화했습니다') !== -1);
});

test('UI: 내보내기·가져오기 왕복, 잘못된 파일은 거부', () => {
  const a = boot();
  addAnyAllowAtTop(a);
  a.$('btn-export').click();
  assert.strictEqual(a.downloads.length, 1);
  assert.strictEqual(a.downloads[0].name, 'fw_policy.json');
  const b = boot();
  assert.strictEqual(b.app.importText(a.downloads[0].text), true);
  assert.strictEqual(b.rows().length, 6);
  assert.strictEqual(b.app.policy.getHistory().length, 1);
  assert.ok(T(b.$('msg')).indexOf('규칙 6개, 이력 1건') !== -1);
  const rowsBefore = b.rows().length;
  assert.strictEqual(b.app.importText('깨진 파일'), false);
  assert.ok(T(b.$('msg')).indexOf('가져오기 실패: JSON 을 읽을 수 없습니다') !== -1);
  assert.strictEqual(b.rows().length, rowsBefore);
  assert.strictEqual(b.app.importText('{"version":1,"rules":[{"src":"x","dst":"Any","service":"Any","action":"deny","purpose":""}],"history":[]}'), false);
  assert.ok(T(b.$('msg')).indexOf('규칙 1: 알 수 없는 주소') !== -1);
});

test('UI: 입력값은 마크업이 아니라 텍스트로만 들어간다 (XSS 방지)', () => {
  const ui = boot();
  const evil = '<img src=x onerror=alert(1)>';
  ui.type('f-src', 'Any'); ui.type('f-dst', 'Any'); ui.type('f-service', 'TCP 1'); ui.type('f-action', 'deny'); ui.type('f-purpose', evil);
  ui.submitRule();
  assert.ok(T(ui.$('rule-6')).indexOf(evil) !== -1);                 // 글자 그대로 보임
  assert.strictEqual(findAll(ui.doc.root, n => n.tagName === 'IMG').length, 0);   // 태그로 해석되지 않음
  ui.$('tab-history').click();
  assert.ok(T(ui.$('history')).indexOf('<img') === -1 || findAll(ui.doc.root, n => n.tagName === 'IMG').length === 0);
});
