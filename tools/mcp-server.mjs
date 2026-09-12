#!/usr/bin/env node
/**
 * mcp-server.mjs - Exposes the compliance engine as an MCP server over stdio.
 * No external dependencies: implements JSON-RPC 2.0 with newline-delimited messages.
 *
 * Register it in an MCP client with:
 *   "oss-compliance": {
 *     "command": "node",
 *     "args": ["<path>/oss-compliance-analyzer/tools/mcp-server.mjs"]
 *   }
 *
 * The LLM orchestrates and explains; it never decides a risk tier - every verdict
 * comes from the deterministic engine.
 */

import { readFileSync } from 'node:fs';
import { parseSpdx } from '../src/spdx.js';
import { analyze } from '../src/risk-engine.js';
import { diffSboms, diffVerdict } from '../src/diff.js';
import { evaluateExpression, checkCompatibility, TIERS } from '../src/license-db.js';
import {
  renderComplianceReport, renderNoticeFile, renderSupplierInquiry, renderDiffReport
} from '../src/report.js';

const cache = new Map();
function loadSbom(path) {
  if (!cache.has(path)) cache.set(path, analyze(parseSpdx(JSON.parse(readFileSync(path, 'utf8')))));
  return cache.get(path);
}

/* --------------------------------------------------------------- tools --- */

const TOOLS = [
  {
    name: 'analyze_sbom',
    description: 'Parse an SPDX 2.x JSON SBOM and return the copyleft risk assessment: score, tier counts, SBOM quality, findings and unresolved licenses.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Absolute path to the .spdx.json file' } },
      required: ['path']
    }
  },
  {
    name: 'list_findings',
    description: 'List compliance findings for an SBOM, optionally filtered by severity or rule id.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
        rule: { type: 'string', description: 'e.g. LIC-006' },
        limit: { type: 'number' }
      },
      required: ['path']
    }
  },
  {
    name: 'find_components',
    description: 'Search components by name, license, risk tier, supplier, or whether they inherit copyleft transitively.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        query: { type: 'string', description: 'Substring match on name / license / purl / supplier' },
        tier: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] },
        taintedOnly: { type: 'boolean', description: 'Only components inheriting copyleft transitively' }
      },
      required: ['path']
    }
  },
  {
    name: 'explain_component',
    description: 'Full detail for one component: effective license, obligations, what it depends on, what depends on it, and any copyleft it inherits.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' }, name: { type: 'string' } },
      required: ['path', 'name']
    }
  },
  {
    name: 'diff_sboms',
    description: 'Compare two SBOM milestones: added/removed components, license and version changes, newly introduced copyleft, new and closed findings.',
    inputSchema: {
      type: 'object',
      properties: { baseline: { type: 'string' }, current: { type: 'string' }, format: { type: 'string', enum: ['md', 'json'], default: 'md' } },
      required: ['baseline', 'current']
    }
  },
  {
    name: 'check_license_compatibility',
    description: 'Check a list of SPDX license ids for known incompatibilities when combined in one distributed work.',
    inputSchema: {
      type: 'object',
      properties: { licenses: { type: 'array', items: { type: 'string' } } },
      required: ['licenses']
    }
  },
  {
    name: 'evaluate_license_expression',
    description: 'Resolve an SPDX license expression (AND / OR / WITH) into a risk tier, obligations and notes.',
    inputSchema: {
      type: 'object',
      properties: { expression: { type: 'string', description: 'e.g. "LGPL-2.1-or-later OR GPL-2.0-or-later"' } },
      required: ['expression']
    }
  },
  {
    name: 'generate_report',
    description: 'Generate a compliance artefact: full report, NOTICE attribution file, supplier inquiry letter, or milestone diff.',
    inputSchema: {
      type: 'object',
      properties: {
        kind: { type: 'string', enum: ['report', 'notice', 'inquiry', 'diff'] },
        path: { type: 'string' },
        baseline: { type: 'string', description: 'only for kind=diff' },
        supplier: { type: 'string' }, ecu: { type: 'string' },
        milestone: { type: 'string' }, preparedBy: { type: 'string' }
      },
      required: ['kind', 'path']
    }
  },
  {
    name: 'release_gate',
    description: 'Decide whether an SBOM passes a release gate. Returns pass/fail with reasons.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        maxCritical: { type: 'number', default: 0 },
        maxHigh: { type: 'number', default: 0 },
        minQuality: { type: 'number', default: 0 },
        allowUnresolved: { type: 'boolean', default: false }
      },
      required: ['path']
    }
  }
];

/* ------------------------------------------------------------- handlers --- */

function callTool(name, args) {
  switch (name) {
    case 'analyze_sbom': {
      const r = loadSbom(args.path);
      return {
        document: r.meta.name, spdxVersion: r.meta.spdxVersion,
        riskScore: r.score.value, riskBand: r.score.band,
        sbomQuality: `${r.quality.score}% (${r.quality.passed}/${r.quality.total})`,
        components: r.components.length,
        tierCounts: r.tierCounts,
        findings: r.counts,
        unresolvedLicenses: r.components.filter(c => !c.declaration.resolved)
          .map(c => `${c.name} ${c.version || ''} (${c.effectiveLicense || 'NOASSERTION'})`),
        topFindings: r.findings.slice(0, 10).map(f => `[${f.severity}] ${f.rule} ${f.title}`),
        obligations: r.obligations
      };
    }

    case 'list_findings': {
      let fs = loadSbom(args.path).findings;
      if (args.severity) fs = fs.filter(f => f.severity === args.severity);
      if (args.rule) fs = fs.filter(f => f.rule === args.rule);
      return {
        total: fs.length,
        findings: fs.slice(0, args.limit || 50).map(f => ({
          rule: f.rule, severity: f.severity, title: f.title, component: f.component,
          detail: f.detail, obligation: f.obligation, action: f.action
        }))
      };
    }

    case 'find_components': {
      let cs = loadSbom(args.path).components;
      if (args.tier) cs = cs.filter(c => c.tier === args.tier);
      if (args.taintedOnly) cs = cs.filter(c => c.taintedBy.length);
      if (args.query) {
        const q = String(args.query).toLowerCase();
        cs = cs.filter(c => (c.name + c.effectiveLicense + (c.purl || '') + c.supplier).toLowerCase().includes(q));
      }
      return {
        total: cs.length,
        components: cs.slice(0, 100).map(c => ({
          name: c.name, version: c.version, license: c.effectiveLicense, tier: c.tier,
          copyleft: c.copyleft, purl: c.purl,
          inheritsCopyleftFrom: c.taintedBy.map(t => `${t.name} (${t.linkKind || 'linkage?'}, ${t.severity})`)
        }))
      };
    }

    case 'explain_component': {
      const r = loadSbom(args.path);
      const c = r.components.find(x => x.name.toLowerCase() === String(args.name).toLowerCase())
        || r.components.find(x => x.name.toLowerCase().includes(String(args.name).toLowerCase()));
      if (!c) return { error: `component "${args.name}" not found` };
      return {
        name: c.name, version: c.version, supplier: c.supplier, purl: c.purl,
        effectiveLicense: c.effectiveLicense, licenseSource: c.licenseSource,
        declared: c.licenseDeclared, concluded: c.licenseConcluded,
        tier: c.tier, copyleft: c.copyleft, category: c.category,
        obligations: c.obligations,
        notes: c.declaration.notes,
        dependsOn: (r.graph.children.get(c.spdxId) || []).map(e => ({
          name: r.byId.get(e.target)?.name, linkage: e.linkage, license: r.byId.get(e.target)?.effectiveLicense
        })),
        usedBy: (r.graph.parents.get(c.spdxId) || []).map(e => ({
          name: r.byId.get(e.source)?.name, linkage: e.linkage
        })),
        inheritsCopyleftFrom: c.taintedBy
      };
    }

    case 'diff_sboms': {
      const d = diffSboms(loadSbom(args.baseline), loadSbom(args.current));
      if (args.format === 'json') return { verdict: diffVerdict(d), counts: d.counts, riskDelta: d.riskDelta,
        added: d.added.map(c => c.name), removed: d.removed.map(c => c.name),
        licenseChanged: d.licenseChanged.map(l => ({ component: l.component.name, from: l.from, to: l.to, escalated: l.escalated })),
        newFindings: d.newFindings.map(f => `[${f.severity}] ${f.rule} ${f.title}`) };
      return { text: renderDiffReport(d) };
    }

    case 'check_license_compatibility': {
      const conflicts = checkCompatibility(args.licenses || []);
      return {
        licenses: args.licenses,
        compatible: conflicts.length === 0,
        conflicts: conflicts.map(c => ({ pair: `${c.a} + ${c.b}`, severity: c.severity, reason: c.reason }))
      };
    }

    case 'evaluate_license_expression': {
      const v = evaluateExpression(args.expression);
      return {
        expression: v.raw, tier: v.tier, category: v.category,
        worstCaseTier: v.worstTier, obligations: v.obligations,
        notes: v.notes, multiLicensed: v.multi,
        terms: v.licenses.map(l => ({ id: l.id, tier: l.tier, category: l.category }))
      };
    }

    case 'generate_report': {
      const r = loadSbom(args.path);
      const meta = { supplier: args.supplier, ecu: args.ecu, milestone: args.milestone, preparedBy: args.preparedBy };
      if (args.kind === 'notice') return { text: renderNoticeFile(r) };
      if (args.kind === 'inquiry') return { text: renderSupplierInquiry(r, meta) };
      if (args.kind === 'diff') {
        if (!args.baseline) return { error: 'baseline path required for kind=diff' };
        return { text: renderDiffReport(diffSboms(loadSbom(args.baseline), r)) };
      }
      return { text: renderComplianceReport(r, meta) };
    }

    case 'release_gate': {
      const r = loadSbom(args.path);
      const unresolved = r.components.filter(c => !c.declaration.resolved);
      const reasons = [];
      if (r.counts.CRITICAL > (args.maxCritical ?? 0)) reasons.push(`critical findings ${r.counts.CRITICAL} > allowed ${args.maxCritical ?? 0}`);
      if (r.counts.HIGH > (args.maxHigh ?? 0)) reasons.push(`high findings ${r.counts.HIGH} > allowed ${args.maxHigh ?? 0}`);
      if (r.quality.score < (args.minQuality ?? 0)) reasons.push(`SBOM quality ${r.quality.score}% < required ${args.minQuality ?? 0}%`);
      if (!args.allowUnresolved && unresolved.length) reasons.push(`${unresolved.length} unresolved license(s)`);
      return { pass: reasons.length === 0, score: r.score.value, band: r.score.band, reasons,
        unresolved: unresolved.map(c => c.name) };
    }

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

/* ------------------------------------------------- JSON-RPC over stdio --- */

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  let i;
  while ((i = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, i).trim();
    buffer = buffer.slice(i + 1);
    if (line) handle(line);
  }
});

function handle(line) {
  let req;
  try { req = JSON.parse(line); }
  catch { return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }

  const { id, method, params } = req;

  if (method === 'initialize') {
    return send({
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'oss-compliance-analyzer', version: '0.1.0' }
      }
    });
  }
  if (method === 'notifications/initialized' || method === 'initialized') return;
  if (method === 'tools/list') return send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  if (method === 'ping') return send({ jsonrpc: '2.0', id, result: {} });

  if (method === 'tools/call') {
    try {
      const out = callTool(params.name, params.arguments || {});
      return send({
        jsonrpc: '2.0', id,
        result: { content: [{ type: 'text', text: typeof out === 'string' ? out : JSON.stringify(out, null, 2) }] }
      });
    } catch (e) {
      return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: `error: ${e.message}` }] } });
    }
  }

  send({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
}
