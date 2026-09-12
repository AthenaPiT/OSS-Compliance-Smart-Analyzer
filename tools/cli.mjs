#!/usr/bin/env node
/**
 * cli.mjs - Headless OSS compliance analyzer. Built for CI and batch use.
 *
 *   node tools/cli.mjs analyze <file.spdx.json> [--format json|md|csv] [--out file]
 *   node tools/cli.mjs report   <file.spdx.json> [--out report.md] [--supplier X] [--ecu Y] [--milestone Z]
 *   node tools/cli.mjs notice   <file.spdx.json> [--out NOTICE]
 *   node tools/cli.mjs inquiry  <file.spdx.json> [--out inquiry.md] [--supplier X]
 *   node tools/cli.mjs diff     <baseline.spdx.json> <current.spdx.json> [--format md|json] [--out file]
 *   node tools/cli.mjs gate     <file.spdx.json> [--max-critical N] [--max-high N] [--min-quality N]
 *
 * Exit codes (gate): 0 = pass, 1 = policy violation, 2 = error.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { parseSpdx } from '../src/spdx.js';
import { analyze } from '../src/risk-engine.js';
import { diffSboms, diffVerdict } from '../src/diff.js';
import {
  renderComplianceReport, renderNoticeFile, renderSupplierInquiry,
  renderComponentsCsv, renderDiffReport
} from '../src/report.js';

const [, , cmd, ...args] = process.argv;

const flag = (name, def = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : def;
};
const has = name => args.includes(`--${name}`) || args.includes(`--${name}=true`);
const positional = () => args
  .filter(a => !a.startsWith('--'))
  .filter((a, i, list) => !/^\d+$/.test(a) || !list[i - 1]?.startsWith('--'));

const fail = msg => { console.error('error: ' + msg); process.exit(2); };

function load(path) {
  try { return analyze(parseSpdx(JSON.parse(readFileSync(path, 'utf8')))); }
  catch (e) { fail(`cannot analyse ${path}: ${e.message}`); }
}

function emit(text, out) {
  if (out) { writeFileSync(out, text); console.log(`written: ${out}`); }
  else console.log(text);
}

const usage = `usage:
  node tools/cli.mjs analyze  <file.spdx.json> [--format json|md|csv] [--out file]
  node tools/cli.mjs report   <file.spdx.json> [--out report.md] [--supplier X] [--ecu Y] [--milestone Z]
  node tools/cli.mjs notice   <file.spdx.json> [--out NOTICE]
  node tools/cli.mjs inquiry  <file.spdx.json> [--out inquiry.md] [--supplier X]
  node tools/cli.mjs diff     <baseline.spdx.json> <current.spdx.json> [--format md|json] [--out file]
  node tools/cli.mjs gate     <file.spdx.json> [--max-critical N] [--max-high N] [--min-quality N]`;

switch (cmd) {
  case 'analyze': {
    const [f] = positional();
    if (!f) fail('missing file. \n' + usage);
    const r = load(f);
    const fmt = flag('format', 'json');
    if (fmt === 'csv') emit(renderComponentsCsv(r), flag('out'));
    else if (fmt === 'md') emit(renderComplianceReport(r, { supplier: flag('supplier'), ecu: flag('ecu'), milestone: flag('milestone') }), flag('out'));
    else emit(JSON.stringify({
      document: r.meta, score: r.score, quality: r.quality,
      summary: {
        components: r.components.length, tierCounts: r.tierCounts, findings: r.counts,
        unresolved: r.components.filter(c => !c.declaration.resolved).length
      },
      findings: r.findings,
      components: r.components.map(c => ({
        name: c.name, version: c.version, purl: c.purl, supplier: c.supplier,
        license: c.effectiveLicense, licenseSource: c.licenseSource, tier: c.tier,
        copyleft: c.copyleft, inherited: c.taintedBy
      }))
    }, null, 2), flag('out'));
    break;
  }

  case 'report': {
    const [f] = positional();
    if (!f) fail('missing file. \n' + usage);
    emit(renderComplianceReport(load(f), {
      supplier: flag('supplier'), ecu: flag('ecu'), milestone: flag('milestone'),
      preparedBy: flag('prepared-by')
    }), flag('out'));
    break;
  }

  case 'notice': {
    const [f] = positional();
    if (!f) fail('missing file. \n' + usage);
    emit(renderNoticeFile(load(f)), flag('out'));
    break;
  }

  case 'inquiry': {
    const [f] = positional();
    if (!f) fail('missing file. \n' + usage);
    emit(renderSupplierInquiry(load(f), {
      supplier: flag('supplier'), ecu: flag('ecu'), milestone: flag('milestone'),
      preparedBy: flag('prepared-by'), dueDate: flag('due-date')
    }), flag('out'));
    break;
  }

  case 'diff': {
    const [a, b] = positional();
    if (!a || !b) fail('need a baseline and a current SBOM. \n' + usage);
    const d = diffSboms(load(a), load(b));
    const fmt = flag('format', 'md');
    if (fmt === 'json') emit(JSON.stringify({ verdict: diffVerdict(d), ...d }, null, 2), flag('out'));
    else emit(renderDiffReport(d), flag('out'));
    break;
  }

  case 'gate': {
    const [f] = positional();
    if (!f) fail('missing file. \n' + usage);
    const r = load(f);
    const maxCritical = Number(flag('max-critical', 0));
    const maxHigh = Number(flag('max-high', 0));
    const minQuality = Number(flag('min-quality', 0));

    const reasons = [];
    if (r.counts.CRITICAL > maxCritical) reasons.push(`critical findings ${r.counts.CRITICAL} > allowed ${maxCritical}`);
    if (r.counts.HIGH > maxHigh) reasons.push(`high findings ${r.counts.HIGH} > allowed ${maxHigh}`);
    if (r.quality.score < minQuality) reasons.push(`SBOM quality ${r.quality.score}% < required ${minQuality}%`);

    const unresolved = r.components.filter(c => !c.declaration.resolved).length;
    if (unresolved > 0 && !has('allow-unresolved')) reasons.push(`${unresolved} unresolved license(s)`);

    if (reasons.length) {
      console.error(`GATE FAILED - ${r.meta.name} (score ${r.score.value}/${r.score.band})`);
      reasons.forEach(x => console.error('  - ' + x));
      process.exit(1);
    }
    console.log(`GATE PASSED - ${r.meta.name} (score ${r.score.value}/${r.score.band}, quality ${r.quality.score}%)`);
    process.exit(0);
  }

  default:
    console.log(usage);
    process.exit(cmd ? 2 : 0);
}
