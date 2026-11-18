// 테스트 실행기: tests/*.test.mjs 를 모두 불러온다. (Node 12 호환: 최상위 await 미사용)
import { readdirSync } from 'fs';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';
import { results } from './helper.mjs';

const dir = dirname(fileURLToPath(import.meta.url));

async function main() {
  const files = readdirSync(dir).filter(f => f.endsWith('.test.mjs')).sort();
  for (const f of files) await import(pathToFileURL(join(dir, f)).href);

  let fail = 0;
  for (const r of results) {
    if (r.error) { fail++; console.log('FAIL', r.name, '\n   ', r.error.message); }
    else console.log('ok  ', r.name);
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  process.exit(fail ? 1 : 0);
}
main();
