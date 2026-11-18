// 화면 조립. document 를 주입받는다(mount) → 브라우저에서는 실제 document, 테스트에서는 가짜 DOM.
import { Policy } from '../core/policy.js';
import { defaultTopology, parseIPv4, zoneOf } from '../core/topology.js';
import { makeH, clear } from './dom.js';
import {
  ACTION_LABEL, FIELD_LABELS, TYPE_LABEL, TYPE_REF, CHANGE_LABEL, SCENARIOS,
  describeJudge, findingsByRule, historyDiff, summarizeEntry, shortTime,
} from './format.js';
import { loadSnapshot, saveSnapshot, parseImport, exportText } from './storage.js';

const DEFAULT_BY = '관리자';

// opts: { storage, now, confirm(msg)->bool, download(filename,text) }
export function mount(doc, opts) {
  const o = opts || {};
  const h = makeH(doc);
  const topo = defaultTopology();
  const root = doc.getElementById('app');
  const storage = o.storage || null;
  const confirmFn = o.confirm || (m => (typeof confirm === 'function' ? confirm(m) : true));
  const downloadFn = o.download || defaultDownload;

  const saved = storage ? loadSnapshot(storage) : null;
  const newPolicy = snap => (snap ? Policy.restore(snap, { now: o.now }) : new Policy(null, { now: o.now }));
  let policy = newPolicy(saved);

  const state = { lastInput: null, lastResult: null, findings: null, focus: [], editNo: null, tab: 'packet', msg: null };

  // ---------- 골격 ----------
  const byInput = h('input', { id: 'by', type: 'text', value: DEFAULT_BY, title: '변경 이력에 남는 변경자' });
  const msgBox = h('div', { id: 'msg', class: 'msg', hidden: true });
  const topoBox = h('div', { class: 'topo' });
  const tbody = h('tbody', { id: 'rules' });
  const bannerBox = h('div', { class: 'banner' });

  const fSrc = h('input', { id: 'f-src', type: 'text', placeholder: 'Any / 구역 / 그룹 / IP', list: 'addr-list' });
  const fDst = h('input', { id: 'f-dst', type: 'text', placeholder: 'Any / 구역 / 그룹 / IP', list: 'addr-list' });
  const fService = h('input', { id: 'f-service', type: 'text', placeholder: '예: TCP 80, 443 / UDP 514 / Any' });
  const fAction = h('select', { id: 'f-action' }, h('option', { value: 'allow' }, '허용'), h('option', { value: 'deny' }, '차단'));
  const fPurpose = h('input', { id: 'f-purpose', type: 'text', placeholder: '목적' });
  const fPos = h('input', { id: 'f-position', type: 'number', min: 1, placeholder: '맨 아래' });
  const fSubmit = h('button', { id: 'f-submit', type: 'submit' }, '추가');
  const fCancel = h('button', { id: 'f-cancel', type: 'button', hidden: true, onClick: () => cancelEdit() }, '취소');
  const formTitle = h('h3', null, '규칙 추가');
  const formErr = h('ul', { id: 'form-err', class: 'err' });

  const pSrc = h('input', { id: 'p-src', type: 'text', value: '10.20.1.20', placeholder: '출발지 IP', list: 'host-list' });
  const pDst = h('input', { id: 'p-dst', type: 'text', value: '203.0.113.10', placeholder: '목적지 IP', list: 'host-list' });
  const pProto = h('select', { id: 'p-proto' }, h('option', { value: 'TCP' }, 'TCP'), h('option', { value: 'UDP' }, 'UDP'));
  const pPort = h('input', { id: 'p-port', type: 'number', min: 1, value: '443' });
  const resultBox = h('div', { id: 'result', class: 'result' });
  const checkBox = h('div', { id: 'check-result' });
  const historyBox = h('div', { id: 'history' });

  const panels = {
    packet: h('div', { id: 'panel-packet' }),
    check: h('div', { id: 'panel-check' }),
    history: h('div', { id: 'panel-history' }),
  };
  const tabBtns = {};
  const tabDefs = [['packet', '패킷 시험'], ['check', '정책 점검'], ['history', '변경 이력']];
  const tabBar = h('div', { class: 'tabs' }, tabDefs.map(([key, label]) => {
    tabBtns[key] = h('button', { id: 'tab-' + key, type: 'button', onClick: () => { state.tab = key; renderTabs(); } }, label);
    return tabBtns[key];
  }));

  const fileInput = h('input', { id: 'file-import', type: 'file', accept: 'application/json,.json', hidden: true, onChange: ev => onFileChosen(ev) });

  // 주소 입력 자동완성 목록
  const addrList = h('datalist', { id: 'addr-list' },
    h('option', { value: 'Any' }),
    topo.zones.map(z => h('option', { value: z.name })),
    topo.groups.map(g => h('option', { value: g.name })),
    topo.hosts.map(x => h('option', { value: x.ip }, x.name)));
  const hostList = h('datalist', { id: 'host-list' }, topo.hosts.map(x => h('option', { value: x.ip }, x.name)));

  const hostSelect = (target, id) => h('select', { id, title: '호스트 빠른 선택', onChange: ev => { if (ev.target.value) target.value = ev.target.value; } },
    h('option', { value: '' }, '호스트 선택…'),
    topo.hosts.map(x => h('option', { value: x.ip }, `${x.name} ${x.ip}`)));

  root.appendChild(h('header', null,
    h('h1', null, '패킷 길찾기'),
    h('p', { class: 'muted' }, '방화벽 정책 시뮬레이터 — 위에서부터 처음 일치하는 규칙 하나만 적용됩니다 (first-match).'),
    h('div', { class: 'toolbar' },
      h('label', null, '변경자 ', byInput),
      h('button', { id: 'btn-export', type: 'button', onClick: () => doExport() }, 'JSON 내보내기'),
      h('button', { id: 'btn-import', type: 'button', onClick: () => fileInput.click() }, 'JSON 가져오기'),
      h('button', { id: 'btn-reset', type: 'button', onClick: () => doReset() }, '기본 정책표로 초기화'),
      fileInput)));
  root.appendChild(msgBox);
  root.appendChild(h('section', null, h('h2', null, '네트워크 구성 (4구역)'), topoBox));
  root.appendChild(h('section', null,
    h('h2', null, '정책표'),
    bannerBox,
    h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, ['번호', '출발지', '목적지', '서비스', '동작', '목적', '점검', '작업'].map(t => h('th', null, t)))),
      tbody)),
    h('form', { id: 'rule-form', class: 'rule-form', onSubmit: ev => onSubmit(ev) },
      formTitle,
      h('div', { class: 'grid' },
        h('label', null, '출발지', fSrc), h('label', null, '목적지', fDst), h('label', null, '서비스', fService),
        h('label', null, '동작', fAction), h('label', null, '목적', fPurpose), h('label', null, '위치(추가만)', fPos)),
      h('div', { class: 'row' }, fSubmit, fCancel), formErr),
    addrList, hostList));
  root.appendChild(h('section', null, tabBar, panels.packet, panels.check, panels.history));

  // 패킷 시험 패널
  panels.packet.appendChild(h('form', { id: 'packet-form', class: 'packet-form', onSubmit: ev => { if (ev && ev.preventDefault) ev.preventDefault(); runJudge(); } },
    h('div', { class: 'grid' },
      h('label', null, '출발지 IP', pSrc, hostSelect(pSrc, 'p-src-pick')),
      h('label', null, '목적지 IP', pDst, hostSelect(pDst, 'p-dst-pick')),
      h('label', null, '프로토콜', pProto), h('label', null, '포트', pPort)),
    h('div', { class: 'row' }, h('button', { id: 'p-run', type: 'submit' }, '길찾기')),
    h('div', { class: 'scenarios' }, h('span', { class: 'muted' }, '예제: '),
      SCENARIOS.map((s, i) => h('button', { id: 'scenario-' + i, type: 'button', class: 'chip', onClick: () => useScenario(s) }, s.label)))));
  panels.packet.appendChild(resultBox);
  panels.check.appendChild(h('div', { class: 'row' },
    h('button', { id: 'btn-check', type: 'button', onClick: () => runCheck() }, '정책 점검'),
    h('span', { class: 'muted' }, '중복·섀도잉·기본 거부·syslog 표준 포트를 검사합니다.')));
  panels.check.appendChild(checkBox);
  panels.history.appendChild(historyBox);

  // ---------- 동작 ----------
  const by = () => byInput.value.trim() || DEFAULT_BY;
  function setMsg(kind, lines) { state.msg = { kind, lines: [].concat(lines) }; renderMsg(); }

  function persist() {
    if (storage && !saveSnapshot(storage, policy.snapshot())) {
      state.msg = { kind: 'err', lines: ['브라우저 저장소를 쓸 수 없어 변경이 새로고침 후 사라집니다. JSON 내보내기로 보관하세요.'] };
    }
  }

  // 변경 후 공통 처리: 저장, 마지막 판정·점검 결과 갱신, 화면 다시 그리기
  function afterChange() {
    persist();
    state.focus = [];
    if (state.lastInput) state.lastResult = policy.judge(state.lastInput);
    if (state.findings !== null) state.findings = policy.check();
    refresh();
  }

  function mutate(res, okText) {
    if (!res.ok) { setMsg('err', res.errors.map(errText)); return false; }
    cancelEdit(true);
    state.msg = { kind: 'ok', lines: [okText] };
    afterChange();
    return true;
  }
  const errText = e => `${FIELD_LABELS[e.field] || e.field}: ${e.error}`;

  function moveBy(no, delta) { const to = no + delta; if (to >= 1 && to <= policy.getRules().length) mutate(policy.moveRule(no, to, { by: by() }), `규칙 ${no}번을 ${to}번으로 이동했습니다`); }
  function remove(no) { if (confirmFn(`규칙 ${no}번을 삭제할까요?`)) mutate(policy.deleteRule(no, { by: by() }), `규칙 ${no}번을 삭제했습니다`); }

  function startEdit(no) {
    const r = policy.getRules().find(x => x.no === no);
    if (!r) return;
    state.editNo = no;
    fSrc.value = r.src; fDst.value = r.dst; fService.value = r.service; fAction.value = r.action; fPurpose.value = r.purpose;
    fPos.value = ''; fPos.disabled = true;
    formTitle.textContent = `규칙 ${no}번 수정`;
    fSubmit.textContent = '저장';
    fCancel.hidden = false;
    clear(formErr);
  }
  function cancelEdit(keepMsg) {
    state.editNo = null;
    fSrc.value = ''; fDst.value = ''; fService.value = ''; fAction.value = 'allow'; fPurpose.value = ''; fPos.value = ''; fPos.disabled = false;
    formTitle.textContent = '규칙 추가';
    fSubmit.textContent = '추가';
    fCancel.hidden = true;
    clear(formErr);
    if (!keepMsg) { state.msg = null; renderMsg(); }
  }

  function onSubmit(ev) {
    if (ev && ev.preventDefault) ev.preventDefault();
    const fields = { src: fSrc.value, dst: fDst.value, service: fService.value, action: fAction.value, purpose: fPurpose.value };
    clear(formErr);
    let res;
    let okText;
    if (state.editNo !== null) {
      const no = state.editNo;
      res = policy.updateRule(no, fields, { by: by() });
      okText = res.ok && res.changed === false ? `규칙 ${no}번: 변경 사항이 없습니다` : `규칙 ${no}번을 수정했습니다`;
    } else {
      const opt = { by: by() };
      if (fPos.value.trim() !== '') opt.position = Number(fPos.value);
      res = policy.addRule(fields, opt);
      okText = res.ok ? `규칙 ${res.rule.no}번을 추가했습니다` : '';
    }
    if (!res.ok) { res.errors.forEach(e => formErr.appendChild(h('li', null, errText(e)))); return; }
    mutate(res, okText);
  }

  function readPacket() { return { src: pSrc.value.trim(), dst: pDst.value.trim(), proto: pProto.value, port: pPort.value }; }
  function runJudge() {
    state.lastInput = readPacket();
    state.lastResult = policy.judge(state.lastInput);
    state.tab = 'packet';
    refresh();
  }
  function useScenario(s) { pSrc.value = s.src; pDst.value = s.dst; pProto.value = s.proto; pPort.value = String(s.port); runJudge(); }
  function runCheck() { state.findings = policy.check(); state.focus = []; state.tab = 'check'; refresh(); }

  function doExport() { downloadFn('fw_policy.json', exportText(policy.snapshot())); setMsg('ok', '정책표와 변경 이력을 JSON 으로 내보냈습니다'); }
  function doReset() {
    if (!confirmFn('정책표를 기본 5행으로 되돌리고 변경 이력도 모두 지웁니다. 계속할까요?')) return;
    policy = newPolicy(null);
    resetViewState();
    state.msg = { kind: 'ok', lines: ['기본 정책표로 초기화했습니다'] };
    persist(); refresh();
  }
  function resetViewState() { state.lastResult = null; state.lastInput = null; state.findings = null; state.focus = []; cancelEdit(true); }
  function importText(text) {
    const p = parseImport(text);
    if (!p.ok) { setMsg('err', '가져오기 실패: ' + p.error); return false; }
    if (!confirmFn('현재 정책표와 변경 이력을 가져온 파일로 바꿉니다. 계속할까요?')) return false;
    policy = newPolicy(p.snapshot);
    resetViewState();
    state.msg = { kind: 'ok', lines: [`가져왔습니다 (규칙 ${p.snapshot.rules.length}개, 이력 ${p.snapshot.history.length}건)`] };
    persist(); refresh();
    return true;
  }
  function onFileChosen(ev) {
    const f = ev.target.files && ev.target.files[0];
    if (!f) return;
    f.text().then(importText, () => setMsg('err', '가져오기 실패: 파일을 읽을 수 없습니다'));
    ev.target.value = '';
  }

  // ---------- 그리기 ----------
  function renderMsg() {
    clear(msgBox);
    if (!state.msg) { msgBox.hidden = true; return; }
    msgBox.hidden = false;
    msgBox.className = 'msg ' + state.msg.kind;
    state.msg.lines.forEach(l => msgBox.appendChild(h('div', null, l)));
  }

  function renderTabs() {
    Object.keys(panels).forEach(k => { panels[k].hidden = k !== state.tab; tabBtns[k].className = k === state.tab ? 'active' : ''; });
  }

  function renderTopology() {
    clear(topoBox);
    const jr = state.lastResult && state.lastResult.ok ? state.lastResult.result : null;
    const zoneBox = z => {
      const hosts = topo.hosts.filter(x => zoneOf(parseIPv4(x.ip), topo) === z.name);
      const cls = ['zone'];
      if (jr && jr.srcZone === z.name) cls.push('src');
      if (jr && jr.dstZone === z.name) cls.push('dst');
      return h('div', { class: cls.join(' ') },
        h('strong', null, z.name), h('div', { class: 'muted' }, z.cidr || '그 외 모든 IP'),
        h('ul', null, hosts.map(x => h('li', null, `${x.name} ${x.ip}`))));
    };
    const [internet, ...inner] = topo.zones;
    topoBox.appendChild(h('div', { class: 'zone-row' }, zoneBox(internet)));
    topoBox.appendChild(h('div', { class: 'fw' }, '방화벽 (정책표 위→아래, 첫 일치 규칙 적용)'));
    topoBox.appendChild(h('div', { class: 'zone-row three' }, inner.map(zoneBox)));
    if (jr) {
      const d = describeJudge(jr, state.lastInput, topo);
      topoBox.appendChild(h('div', { class: 'pathline ' + jr.action }, `${d.pathText} : ${d.headline}`));
    }
  }

  function renderTable() {
    clear(tbody);
    clear(bannerBox);
    const rules = policy.getRules();
    const jr = state.lastResult && state.lastResult.ok ? state.lastResult.result : null;
    const traced = {};
    if (jr) jr.trace.forEach(t => { traced[t.no] = t.matched ? 'hit' : 'miss'; });
    const byRule = findingsByRule(state.findings);
    if (state.findings) {
      state.findings.filter(f => f.type === 'no-default-deny').forEach(f => bannerBox.appendChild(h('div', { class: 'msg err' }, f.message)));
    }
    if (rules.length === 0) tbody.appendChild(h('tr', null, h('td', { colSpan: 8, class: 'muted' }, '규칙이 없습니다. 아래에서 추가하세요.')));
    rules.forEach(r => {
      const cls = [];
      if (traced[r.no]) cls.push(traced[r.no]);
      if (state.focus.indexOf(r.no) !== -1) cls.push('focus');
      const fs = byRule[r.no] || [];
      tbody.appendChild(h('tr', { id: 'rule-' + r.no, class: cls.join(' ') },
        h('td', null, String(r.no)), h('td', null, r.src), h('td', null, r.dst), h('td', null, r.service),
        h('td', null, h('span', { class: 'badge ' + r.action }, ACTION_LABEL[r.action])),
        h('td', null, r.purpose),
        h('td', null, fs.map(f => h('span', { class: 'badge warn', title: f.message }, TYPE_LABEL[f.type]))),
        h('td', { class: 'actions' },
          h('button', { type: 'button', title: '위로', id: `up-${r.no}`, onClick: () => moveBy(r.no, -1) }, '▲'),
          h('button', { type: 'button', title: '아래로', id: `down-${r.no}`, onClick: () => moveBy(r.no, 1) }, '▼'),
          h('button', { type: 'button', id: `edit-${r.no}`, onClick: () => startEdit(r.no) }, '수정'),
          h('button', { type: 'button', id: `del-${r.no}`, onClick: () => remove(r.no) }, '삭제'))));
    });
  }

  function renderResult() {
    clear(resultBox);
    const r = state.lastResult;
    if (!r) { resultBox.appendChild(h('p', { class: 'muted' }, '패킷을 입력하고 “길찾기”를 누르거나 예제 버튼을 눌러 보세요.')); return; }
    if (!r.ok) { resultBox.appendChild(h('p', { class: 'msg err' }, r.error)); return; }
    const d = describeJudge(r.result, state.lastInput, topo);
    resultBox.appendChild(h('div', { class: 'verdict ' + d.action }, d.headline));
    resultBox.appendChild(h('p', null, d.packetText));
    resultBox.appendChild(h('p', null, '경로: ' + d.pathText));
    resultBox.appendChild(h('ol', { class: 'trace' }, d.traceLines.map(l => h('li', null, l))));
    if (d.stoppedNote) resultBox.appendChild(h('p', { class: 'muted' }, d.stoppedNote));
    d.warnings.forEach(w => resultBox.appendChild(h('p', { class: 'msg err' }, w)));
  }

  function renderCheck() {
    clear(checkBox);
    if (state.findings === null) { checkBox.appendChild(h('p', { class: 'muted' }, '아직 점검하지 않았습니다.')); return; }
    if (state.findings.length === 0) { checkBox.appendChild(h('p', { class: 'msg ok' }, '경고 없음 — 점검을 통과했습니다')); return; }
    checkBox.appendChild(h('p', null, `경고 ${state.findings.length}건 (항목을 누르면 관련 규칙이 표에서 강조됩니다)`));
    checkBox.appendChild(h('ul', { class: 'findings' }, state.findings.map((f, i) =>
      h('li', { id: 'finding-' + i, onClick: () => { state.focus = [f.no, f.by].filter(n => n !== null && n !== undefined); renderTable(); } },
        h('span', { class: 'badge warn' }, TYPE_LABEL[f.type]), ' ', f.message, ' ', h('span', { class: 'muted' }, `[${TYPE_REF[f.type]}]`)))));
  }

  function renderHistory() {
    clear(historyBox);
    const entries = policy.getHistory();
    if (entries.length === 0) { historyBox.appendChild(h('p', { class: 'muted' }, '변경 이력이 없습니다. (초기 정책표는 이력에 남기지 않습니다)')); return; }
    historyBox.appendChild(h('p', { class: 'muted' }, `총 ${entries.length}건 · 최신이 위`));
    historyBox.appendChild(h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, ['시각(UTC)', '종류', '규칙', '변경자', '내용'].map(t => h('th', null, t)))),
      h('tbody', null, entries.slice().reverse().map((e, i) => h('tr', { id: 'hist-' + i },
        h('td', { title: e.time }, shortTime(e.time)),
        h('td', null, CHANGE_LABEL[e.type]),
        h('td', null, String(e.ruleNo)),
        h('td', null, e.by),
        h('td', null, summarizeEntry(e),
          h('details', null, h('summary', null, '변경 전·후'),
            h('ul', null, historyDiff(e).map(d => h('li', null, `${d.field}: ${d.before} → ${d.after}`)))))))))));
  }

  function refresh() { renderMsg(); renderTopology(); renderTable(); renderResult(); renderCheck(); renderHistory(); renderTabs(); }

  refresh();
  return { get policy() { return policy; }, importText, exportText: () => exportText(policy.snapshot()), state };
}

function defaultDownload(filename, text) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// 브라우저에서 직접 실행될 때만 자동 마운트
if (typeof document !== 'undefined' && document.getElementById && document.getElementById('app')) {
  let store = null;
  try { store = window.localStorage; } catch (e) { store = null; }
  mount(document, { storage: store });
}
