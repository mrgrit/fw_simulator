// 아주 얇은 DOM 헬퍼. 문자열은 항상 텍스트 노드로 넣는다(innerHTML 미사용 → 입력값이 마크업으로 해석되지 않음).
const DIRECT = ['id', 'value', 'type', 'placeholder', 'title', 'disabled', 'hidden', 'checked', 'selected',
  'colSpan', 'min', 'max', 'rows', 'htmlFor', 'href', 'download', 'name', 'multiple', 'accept'];

export function makeH(doc) {
  function add(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(c => add(node, c)); return; }
    node.appendChild(typeof child === 'object' ? child : doc.createTextNode(String(child)));
  }
  return function h(tag, props) {
    const node = doc.createElement(tag);
    const p = props || {};
    Object.keys(p).forEach(k => {
      const v = p[k];
      if (v === undefined || v === null) return;
      if (k.slice(0, 2) === 'on') node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'class') node.className = v;
      else if (DIRECT.indexOf(k) !== -1) node[k] = v;
      else node.setAttribute(k, v);
    });
    for (let i = 2; i < arguments.length; i++) add(node, arguments[i]);
    return node;
  };
}

export function clear(node) { node.textContent = ''; }
