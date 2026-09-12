/**
 * Headless smoke test: runs the analyzer against the sample SBOM and asserts
 * that the key copyleft rules fire. Run with:  npm run smoke
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseSpdx } from '../src/spdx.js';
import { analyze } from '../src/risk-engine.js';
import { evaluateExpression } from '../src/license-db.js';
import { diffSboms, diffVerdict } from '../src/diff.js';
import { renderComplianceReport, renderNoticeFile } from '../src/report.js';

const here = dirname(fileURLToPath(import.meta.url));
let failures = 0;
const check = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' - ' + extra : ''}`);
  if (!cond) failures++;
};

/* ------------------------------------------------- expression evaluator --- */
const cases = [
  ['GPL-2.0-only', 'CRITICAL'],
  ['GPL-2.0-or-later WITH u-boot-exception-2.0', 'HIGH'],
  ['GPL-3.0-only WITH GCC-exception-3.1', 'HIGH'],
  ['GPL-2.0-only WITH Linux-syscall-note', 'CRITICAL'],
  ['LGPL-2.1-or-later OR GPL-2.0-or-later', 'HIGH'],
  ['GPL-2.0-or-later AND LGPL-2.1-or-later', 'CRITICAL'],
  ['MIT', 'LOW'],
  ['Apache-2.0', 'LOW'],
  ['AGPL-3.0-only', 'CRITICAL'],
  ['NOASSERTION', 'UNKNOWN'],
  ['LicenseRef-Foo', 'UNKNOWN'],
  ['(MIT OR Apache-2.0) AND GPL-2.0-only', 'CRITICAL']
];
for (const [expr, expected] of cases) {
  const v = evaluateExpression(expr);
  check(`evaluate("${expr}") => ${expected}`, v.tier === expected, `got ${v.tier}`);
}

/* ------------------------------------------------------------ full model --- */
const raw = JSON.parse(readFileSync(join(here, '..', 'samples', 'sample-ivisystem.spdx.json'), 'utf8'));
const sbom = parseSpdx(raw);
const r = analyze(sbom);

console.log(`\nDocument: ${sbom.meta.name} (SPDX ${sbom.meta.spdxVersion})`);
console.log(`Components: ${r.components.length}, relationships: ${r.graph.edges.length}, roots: ${r.roots.join(', ')}`);
console.log(`Risk score: ${r.score.value} (${r.score.band})  SBOM quality: ${r.quality.score}%`);
console.log(`Findings: CRITICAL=${r.counts.CRITICAL} HIGH=${r.counts.HIGH} MEDIUM=${r.counts.MEDIUM}`);
console.log('\nTop findings:');
r.findings.slice(0, 8).forEach(f => console.log(`  [${f.severity}] ${f.rule} ${f.title}`));

check('parses all packages', sbom.packages.length === raw.packages.length, `${sbom.packages.length}`);
check('root detected', r.roots.includes('SPDXRef-Pkg-IVI-HMI-Application'));
check('AGPL detected as critical', r.components.find(c => c.name === 'eclipse-mosquitto-client')?.tier === 'CRITICAL');
check('AGPL taints telematics-agent',
  r.byId.get('SPDXRef-Pkg-telematics-agent')?.taintedBy.some(t => t.name === 'eclipse-mosquitto-client'));
check('LGPL statically linked raises LIC-009', r.findings.some(f => f.rule === 'LIC-009'));
check('unknown license raises LIC-003', r.findings.some(f => f.rule === 'LIC-003'));
check('custom license text raises LIC-004', r.findings.some(f => f.rule === 'LIC-004'));
check('multi-license election raises LIC-007', r.findings.some(f => f.rule === 'LIC-007'));
check('license conflict raises LIC-005', r.findings.some(f => f.rule === 'LIC-005'));
check('copyleft propagation raises LIC-006', r.findings.some(f => f.rule === 'LIC-006'));
check('NTIA quality checks present', r.quality.checks.length === 12);
check('risk score in range', r.score.value > 0 && r.score.value <= 100, String(r.score.value));

/* ------------------------------------------------------------ diff --- */
const old = analyze(parseSpdx(JSON.parse(
  readFileSync(join(here, '..', 'samples', 'sample-ivisystem-4.1.0.spdx.json'), 'utf8'))));
const d = diffSboms(old, r);
console.log(`\nDiff 4.1.0 -> 4.2.0: ${diffVerdict(d).text} (risk ${d.riskDelta >= 0 ? '+' : ''}${d.riskDelta})`);

const names = arr => arr.map(c => c.name);
check('diff detects added AGPL component', names(d.added).includes('eclipse-mosquitto-client'));
check('diff detects removed component', names(d.removed).includes('gpsd'));
check('diff detects license change', d.licenseChanged.some(l => l.component.name === 'OpenSSL'));
check('diff flags escalation', d.licenseChanged.some(l => l.escalated));
check('diff detects regression to unresolved', names(d.regressed).includes('legacy-codec'));
check('diff detects version bump', d.versionChanged.some(v => v.component.name === 'Qt'));
check('diff reports new critical findings', d.counts.newCritical > 0, String(d.counts.newCritical));

/* ---------------------------------------------------------- report --- */
const md = renderComplianceReport(r, { ecu: 'Cockpit ECU', milestone: 'C-Sample' });
check('report contains verdict', /Risk score \d+\/100/.test(md));
check('report contains obligation checklist', /Obligation checklist/.test(md));
check('report contains source-offer section', /Source-offer package/.test(md));
check('notice file contains attributions', /NOTICES AND ATTRIBUTIONS/.test(renderNoticeFile(r)));

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
