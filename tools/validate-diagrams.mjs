/**
 * validate-diagrams.mjs - Parse every Mermaid block in the design docs and report syntax
 * errors. Dev-only; needs `mermaid` and `jsdom`.
 *
 *   JSDOM_ENTRY=… MERMAID_ENTRY=… node tools/validate-diagrams.mjs
 */
import { readFileSync } from 'node:fs';
import { readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const docsRoot = join(here, '..', 'docs');

const load = (name, fallback) =>
  import(process.env[name] ? pathToFileURL(process.env[name]).href : fallback);

let JSDOM, mermaid;
try {
  ({ JSDOM } = await load('JSDOM_ENTRY', 'jsdom'));
  mermaid = (await load('MERMAID_ENTRY', 'mermaid')).default;
} catch {
  console.log('mermaid/jsdom not installed - skipping diagram validation.');
  process.exit(0);
}

const dom = new JSDOM('<!doctype html><html><body></body></html>', { pretendToBeVisual: true });
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;
global.HTMLElement = dom.window.HTMLElement;
global.SVGElement = dom.window.SVGElement;
global.Element = dom.window.Element;
global.Node = dom.window.Node;
global.getComputedStyle = dom.window.getComputedStyle.bind(dom.window);
global.DOMParser = dom.window.DOMParser;
global.requestAnimationFrame = cb => setTimeout(() => cb(Date.now()), 16);

mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const walk = d => readdirSync(d).flatMap(f => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : p.endsWith('.md') ? [p] : [];
});

const files = walk(docsRoot);
let total = 0, failed = 0;

for (const file of files) {
  const md = readFileSync(file, 'utf8');
  const re = /```mermaid\n([\s\S]*?)```/g;
  let m, i = 0;
  while ((m = re.exec(md))) {
    i++; total++;
    const code = m[1];
    const kind = code.trim().split('\n')[0].slice(0, 40);
    try {
      await mermaid.parse(code);
      console.log(`PASS  ${file.replace(docsRoot, 'docs')} #${i}  ${kind}`);
    } catch (e) {
      failed++;
      console.log(`FAIL  ${file.replace(docsRoot, 'docs')} #${i}  ${kind}`);
      console.log(`      ${String(e.message).split('\n').slice(0, 4).join('\n      ')}`);
    }
  }
}

console.log(`\n${total} diagram(s): ${total - failed} valid, ${failed} invalid`);
process.exit(failed ? 1 : 0);
