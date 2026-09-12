/**
 * UI smoke test: loads index.html in jsdom, runs src/app.js, loads the demo SBOM and
 * asserts the dashboard rendered. Requires jsdom (dev only).
 *
 *   NODE_PATH=<workspace>/node_modules node tools/ui-smoke-test.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// jsdom is dev-only. Resolve it from JSDOM_ENTRY if it is not installed locally.
let JSDOM;
try {
  ({ JSDOM } = await import(
    process.env.JSDOM_ENTRY ? pathToFileURL(process.env.JSDOM_ENTRY).href : 'jsdom'));
} catch {
  console.log('jsdom not available - skipping UI smoke test (npm i -D jsdom to enable).');
  process.exit(0);
}

let failures = 0;
const check = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' - ' + extra : ''}`);
  if (!cond) failures++;
};

const html = readFileSync(join(root, 'index.html'), 'utf8');
const dom = new JSDOM(html, { url: 'http://localhost/', pretendToBeVisual: true });
const { window } = dom;

const sample = JSON.parse(readFileSync(join(root, 'samples', 'sample-ivisystem.spdx.json'), 'utf8'));

global.window = window;
global.document = window.document;
global.requestAnimationFrame = cb => setTimeout(() => cb(Date.now()), 16);
global.cancelAnimationFrame = id => clearTimeout(id);
global.Blob = window.Blob;
global.URL = window.URL;
global.FileReader = window.FileReader;
const baseline = JSON.parse(readFileSync(join(root, 'samples', 'sample-ivisystem-4.1.0.spdx.json'), 'utf8'));
global.fetch = async url => ({
  json: async () => (String(url).includes('4.1.0') ? baseline : sample)
});
global.CustomEvent = window.CustomEvent;
global.Event = window.Event;
global.MouseEvent = window.MouseEvent;
global.getComputedStyle = window.getComputedStyle.bind(window);

const errors = [];
window.addEventListener('error', e => errors.push(e.message));

await import('../src/app.js');

document.querySelector('#btn-sample').click();
await new Promise(r => setTimeout(r, 400));

const q = s => document.querySelector(s);
const qa = s => [...document.querySelectorAll(s)];

check('no runtime errors', errors.length === 0, errors.join('; '));
check('dashboard visible', q('#dashboard').hidden === false);
check('dropzone hidden', q('#dropzone').hidden === true);
check('header shows document', /IVI-Cockpit/.test(q('#hdr-sub').textContent), q('#hdr-sub').textContent);

const kpis = qa('#kpis .kpi-card');
check('6 KPI cards rendered', kpis.length === 6, String(kpis.length));
check('risk score present', /\d+/.test(kpis[0].querySelector('.value').textContent),
  kpis[0].querySelector('.value').textContent);

check('license chart bars', qa('#license-chart .bar-row').length > 5,
  String(qa('#license-chart .bar-row').length));
check('quality checks rendered', qa('#quality tbody tr').length === 12,
  String(qa('#quality tbody tr').length));

const findingRows = qa('#findings tbody tr');
check('findings rendered', findingRows.length > 10, String(findingRows.length));
check('critical badge present', qa('#findings .badge.CRITICAL').length > 0);

const compRows = qa('#components tbody tr');
check('component inventory rendered', compRows.length === 42, String(compRows.length));

const svg = q('#graph svg');
check('graph svg created', !!svg);
const circles = qa('#graph svg circle');
check('graph nodes drawn', circles.length > 20, String(circles.length));
check('graph edges drawn', qa('#graph svg line').length > 20, String(qa('#graph svg line').length));
check('graph stat label', /nodes/.test(q('#g-stat').textContent), q('#g-stat').textContent);

// Filter interaction
q('#c-tier').value = 'CRITICAL';
q('#c-tier').dispatchEvent(new window.Event('change'));
const critRows = qa('#components tbody tr');
check('tier filter narrows inventory', critRows.length > 0 && critRows.length < 42, String(critRows.length));

// Detail panel
q('#c-tier').value = '';
q('#c-tier').dispatchEvent(new window.Event('change'));
const firstLink = qa('#components tbody [data-goto]')[0];
firstLink.click();
check('detail panel opens', q('#detail').classList.contains('open'));
check('detail shows license', /Effective license/.test(q('#detail-body').textContent));

// Milestone diff
q('#btn-sample-diff').click();
await new Promise(r => setTimeout(r, 400));

const diffCard = q('#diff-card');
check('diff card rendered', /Milestone diff/.test(diffCard.textContent), diffCard.textContent.slice(0, 80));
check('diff shows new component', /eclipse-mosquitto-client/.test(diffCard.textContent));
check('diff shows removed component', /gpsd/.test(diffCard.textContent));
check('diff shows license change', /OpenSSL/.test(diffCard.textContent));
check('diff verdict is critical', /CRITICAL/.test(diffCard.textContent));

console.log(`\n${failures === 0 ? 'ALL UI CHECKS PASSED' : failures + ' UI CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
