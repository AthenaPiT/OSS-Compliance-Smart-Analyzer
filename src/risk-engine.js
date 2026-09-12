/**
 * risk-engine.js - Copyleft risk assessment over an SPDX SBOM.
 *
 * Pipeline:
 *   1. resolve effective license per component
 *   2. classify copyleft strength
 *   3. propagate copyleft obligations along the dependency graph (static vs dynamic link)
 *   4. detect license incompatibilities inside each distributed unit
 *   5. emit findings + obligations + a 0-100 risk score
 */

import { evaluateExpression, classifyLicense, inspectLicenseText, checkCompatibility, TIERS } from './license-db.js';
import { buildDependencyGraph, checkSbomQuality } from './spdx.js';

const STRONG = new Set(['strong-copyleft', 'network-copyleft']);
const WEAK = new Set(['weak-copyleft', 'file-copyleft']);

/** Which license field should win, in order. */
const RESOLUTION_ORDER = ['licenseConcluded', 'licenseDeclared', 'licenseInfoFromFiles'];

export function analyze(sbom) {
  const graph = buildDependencyGraph(sbom);
  const quality = checkSbomQuality(sbom);
  const extractedById = new Map(sbom.extractedLicenses.map(l => [l.id, l]));

  /* ---------------------------------------------- 1. per-component license */
  const hasExtractedText = id => {
    const rec = extractedById.get(id) || extractedById.get(id.toLowerCase());
    return !!rec?.text;
  };

  const components = sbom.packages.map(p => {
    const taken = pickLicense(p);
    const raw = evaluateExpression(taken.value);
    // A LicenseRef whose terms were supplied in hasExtractedLicensingInfos counts as
    // "resolved for copyleft purposes" - it still needs legal review, but it is not an
    // unknown-unknown.
    const stillUnresolved = raw.licenses.length
      ? raw.licenses.some(l => !l.resolved && !hasExtractedText(l.id))
      : !!raw.unresolved;
    const verdict = { ...raw, resolved: !stillUnresolved };
    const unverifiedText = scanExtractedText(verdict, extractedById);
    return {
      ...p,
      effectiveLicense: taken.value,
      licenseSource: taken.source,
      declaration: verdict,
      tier: verdict.tier,
      rank: verdict.rank,
      category: verdict.category,
      obligations: verdict.obligations,
      copyleft: STRONG.has(verdict.category) ? 'strong'
        : WEAK.has(verdict.category) ? 'weak'
        : verdict.category === 'copyleft-with-exception' ? 'weak' : 'none',
      unverifiedText,
      isRoot: sbom.roots.includes(p.spdxId),
      taintedBy: [],
      taintedSeverity: null,
      reaches: 0
    };
  });

  const byId = new Map(components.map(c => [c.spdxId, c]));

  /* ------------------------------------------- 2. copyleft propagation */
  // A strong copyleft child statically linked into a parent taints the parent.
  // A weak copyleft child creates obligations on the parent but does not relicense it.
  const findings = [];
  const propagationPaths = [];

  for (const c of components) {
    if (c.copyleft !== 'strong' && c.copyleft !== 'weak') continue;

    const ancestors = collectAncestors(c.spdxId, graph, byId);
    for (const anc of ancestors) {
      const top = anc.node;
      if (top.spdxId === c.spdxId) continue;
      const linkKind = anc.linkKind;              // edge closest to the copyleft component
      const staticLink = linkKind === 'static' || linkKind === 'unknown';
      const severity = c.copyleft === 'strong' && staticLink ? 'CRITICAL'
        : c.copyleft === 'strong' ? 'HIGH' : 'MEDIUM';

      top.taintedBy.push({ from: c.spdxId, name: c.name, license: c.effectiveLicense, severity, linkKind, hops: anc.hops });
      if (!top.taintedSeverity || TIERS[severity].rank > TIERS[top.taintedSeverity].rank) {
        top.taintedSeverity = severity;
      }
      propagationPaths.push({ source: c, target: top, severity, linkKind });
    }
  }

  // Findings: strong copyleft reaching a proprietary / closed component
  for (const p of propagationPaths) {
    const target = p.target;
    // Report propagation once per distributed unit (root), not once per intermediate hop.
    if (!target.isRoot) continue;
    const closed = /proprietary|licenseref-/i.test(target.effectiveLicense || '') ||
                   target.category === 'proprietary' || target.category === 'custom-ref';
    if (p.severity === 'CRITICAL' || (p.severity === 'HIGH' && closed)) {
      findings.push({
        id: `PROP-${p.source.spdxId}-${target.spdxId}`,
        rule: 'LIC-006',
        severity: 'CRITICAL',
        title: `${p.source.copyleft === 'strong' ? 'Strong' : 'Weak'} copyleft from "${p.source.name}" propagates into "${target.name}"`,
        component: target.name,
        componentId: target.spdxId,
        detail: `"${p.source.name}" (${p.source.effectiveLicense}, ${p.source.copyleft} copyleft) is ${
          p.linkKind === 'dynamic' ? 'dynamically linked into' :
          p.linkKind === 'static' ? 'statically linked into' :
          'a dependency of (linkage not declared)'} "${target.name}" (${
          target.effectiveLicense || 'no license asserted'}).`,
        obligation: p.linkKind === 'dynamic'
          ? 'Confirm dynamic linking is real (separate shared object, replaceable by the user).'
          : 'Static/unknown linkage: the combined binary is a derivative work - full corresponding source of the combined work must be offered.',
        action: closed
          ? 'Replace the component, obtain a commercial license, or isolate it in a separate process communicating at arms length.'
          : 'Confirm with legal, then prepare the source-offer package.'
      });
    }
  }

  // Findings: weak copyleft (LGPL) statically linked
  for (const p of propagationPaths) {
    if (p.severity !== 'MEDIUM') continue;
    if (p.target.isRoot !== true && !p.target.taintedSeverity) continue;
    if (!/lgpl/i.test(p.source.effectiveLicense || '')) continue;
    if (p.linkKind === 'dynamic') continue;
      findings.push({
        id: `LGPL-${p.source.spdxId}-${p.target.spdxId}`,
        rule: 'LIC-009',
      severity: 'HIGH',
      title: `LGPL component "${p.source.name}" linked without a declared relinking mechanism`,
      component: p.source.name,
      componentId: p.source.spdxId,
      detail: `"${p.source.name}" (${p.source.effectiveLicense}) is consumed by "${
        p.target.name}". Linkage is ${p.linkKind === 'unknown' ? 'not declared in the SBOM' : 'static'}.`,
      obligation: 'Provide the object files (or a replaceable shared library) so the end user can relink against a modified version of the library, plus the license text and a modification notice.',
      action: 'Ask the supplier for the relinking mechanism, or switch to dynamic linking.'
    });
  }

  /* ------------------------------------------- 3. per-component findings */
  for (const c of components) {
    // Critical copyleft present at all
    if (STRONG.has(c.category)) {
      findings.push({
        id: `COPY-${c.spdxId}`,
        rule: 'LIC-001',
        severity: c.category === 'network-copyleft' ? 'CRITICAL' : 'CRITICAL',
        title: `${c.category === 'network-copyleft' ? 'Network copyleft' : 'Strong copyleft'} component: ${c.name}`,
        component: c.name,
        componentId: c.spdxId,
        detail: `${c.name} ${c.version} is licensed "${c.effectiveLicense}". ${
          c.category === 'network-copyleft'
            ? 'AGPL/SSPL obligations extend to users interacting with the software over a network.'
            : 'Distribution of the ECU to the OEM is a distribution event; the combined work must be relicensed.'}`,
        obligation: (c.obligations || []).join('; ') || 'See license text.',
        action: 'Confirm with legal; verify the component is isolated or that the source offer exists.'
      });
    }

    // Unknown / NOASSERTION
    if (!c.declaration.resolved) {
      findings.push({
        id: `UNK-${c.spdxId}`,
        rule: 'LIC-003',
        severity: 'HIGH',
        title: `Unresolved license for ${c.name}`,
        component: c.name,
        componentId: c.spdxId,
        detail: `Effective license is "${c.effectiveLicense || 'empty'}" (source field: ${c.licenseSource}).`,
        obligation: 'Resolve the license from the upstream project, the source headers, or a scanner before release.',
        action: 'Request a corrected SBOM from the supplier. Unresolved licenses are a release blocker under ASPICE / ISO 26262 process gates.'
      });
    }

    // Custom LicenseRef with copyleft text
    if (c.unverifiedText) {
      findings.push({
        id: `REF-${c.spdxId}`,
        rule: 'LIC-004',
        severity: c.unverifiedText.tier === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        title: `Custom license text on ${c.name} shows copyleft indicators`,
        component: c.name,
        componentId: c.spdxId,
        detail: c.unverifiedText.hint,
        obligation: 'Have legal review the extracted license text.',
        action: 'Do not classify as permissive until the full text has been reviewed.'
      });
    }

    // Multi-license election
    if (c.declaration.multi) {
      findings.push({
        id: `MULTI-${c.spdxId}`,
        rule: 'LIC-007',
        severity: 'MEDIUM',
        title: `${c.name} is multi-licensed - election must be documented`,
        component: c.name,
        componentId: c.spdxId,
        detail: `Declared "${c.effectiveLicense}". The tool scored the most favourable option.`,
        obligation: 'Record the elected license in the compliance file and ship the corresponding notice.',
        action: 'Confirm the election with the supplier; the shipped license determines your obligations.'
      });
    }

    // Missing copyright
    if (!c.copyright || /NOASSERTION/i.test(c.copyright)) {
      findings.push({
        id: `CPY-${c.spdxId}`,
        rule: 'LIC-008',
        severity: 'MEDIUM',
        title: `Missing copyright text for ${c.name}`,
        component: c.name,
        componentId: c.spdxId,
        detail: 'copyrightText is empty or NOASSERTION.',
        obligation: 'All attribution notices must be reproduced in the NOTICE file.',
        action: 'Request the copyright statements from the supplier.'
      });
    }
  }

  /* ------------------------------------------- 4. incompatibility conflicts */
  const units = sbom.roots.length ? sbom.roots : components.slice(0, 1).map(c => c.spdxId);
  for (const rootId of units) {
    const subtree = collectSubtree(rootId, graph, byId);
    const licenses = subtree.map(c => c.effectiveLicense)
      .flatMap(v => String(v || '').split(/\s+(?:AND|OR)\s+/i))
      .map(v => v.replace(/[()]/g, '').replace(/WITH\s+\S+/i, '').trim())
      .filter(Boolean);
    for (const conflict of checkCompatibility(licenses)) {
      findings.push({
        id: `CONF-${rootId}-${conflict.a}-${conflict.b}`,
        rule: 'LIC-005',
        severity: conflict.severity,
        title: `License incompatibility: ${conflict.a} vs ${conflict.b}`,
        component: byId.get(rootId)?.name || rootId,
        componentId: rootId,
        detail: conflict.reason,
        obligation: 'Incompatible licenses cannot be combined in a single distributed work.',
        action: 'Isolate the components into separate executables / processes, or replace one of them.'
      });
    }
  }

  /* ------------------------------------------- 5. aggregation */
  const tierCounts = {};
  const licenseStats = new Map();
  for (const c of components) {
    tierCounts[c.tier] = (tierCounts[c.tier] || 0) + 1;
    const key = c.effectiveLicense || 'NOASSERTION';
    const entry = licenseStats.get(key) || { id: key, count: 0, tier: c.tier, components: [] };
    entry.count++;
    entry.components.push(c.name);
    if (c.rank > (TIERS[entry.tier]?.rank || 0)) entry.tier = c.tier;
    licenseStats.set(key, entry);
  }

  const obligationSet = new Set();
  for (const c of components) (c.obligations || []).forEach(o => obligationSet.add(o));

  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));

  const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });

  const score = computeScore(components, counts, quality);

  return {
    meta: sbom.meta,
    quality,
    components,
    byId,
    graph,
    findings,
    counts,
    score,
    tierCounts,
    licenseStats: [...licenseStats.values()].sort((a, b) => b.count - a.count),
    obligations: [...obligationSet],
    roots: sbom.roots,
    warnings: sbom.warnings
  };
}

/* ------------------------------------------------------------- helpers --- */

function pickLicense(p) {
  for (const field of RESOLUTION_ORDER) {
    const v = p[field];
    if (Array.isArray(v) ? v.length : (v && !/^noassertion$/i.test(v))) {
      return { value: Array.isArray(v) ? v.join(' AND ') : v, source: field };
    }
  }
  return { value: 'NOASSERTION', source: 'none' };
}

function scanExtractedText(verdict, extractedById) {
  for (const l of verdict.licenses) {
    if (!/^licenseref-/i.test(l.id || '')) continue;
    const rec = extractedById.get(l.id) || extractedById.get(l.id.toLowerCase());
    if (rec?.text) {
      const hit = inspectLicenseText(rec.text);
      if (hit) return { ...hit, licenseId: l.id };
    }
  }
  return null;
}

/**
 * All ancestors of `id` (walking the parent direction), with the linkage type of the
 * edge adjacent to `id` and the hop distance. Cycle-safe, depth capped.
 */
function collectAncestors(id, graph, byId, maxDepth = 10) {
  const out = [];
  const best = new Map([[id, 0]]);
  const queue = [{ id, hops: 0, linkKind: null }];
  let guard = 0;

  while (queue.length && guard++ < 50000) {
    const cur = queue.shift();
    if (cur.hops >= maxDepth) continue;
    for (const e of graph.parents.get(cur.id) || []) {
      const parent = byId.get(e.source);
      if (!parent || parent.spdxId === id) continue;
      const linkKind = cur.hops === 0 ? e.linkage : cur.linkKind;
      const hops = cur.hops + 1;
      const prev = best.get(parent.spdxId);
      if (prev !== undefined && prev <= hops) continue;
      best.set(parent.spdxId, hops);
      out.push({ node: parent, linkKind, hops });
      queue.push({ id: parent.spdxId, hops, linkKind });
    }
  }
  return out;
}

function collectSubtree(rootId, graph, byId, maxNodes = 4000) {
  const out = [];
  const seen = new Set([rootId]);
  const stack = [rootId];
  while (stack.length && out.length < maxNodes) {
    const id = stack.pop();
    const c = byId.get(id);
    if (c) out.push(c);
    for (const e of graph.children.get(id) || []) {
      if (!seen.has(e.target)) { seen.add(e.target); stack.push(e.target); }
    }
  }
  return out;
}

/**
 * Normalised 0-100 risk score. Deliberately density-based so that the score does not
 * simply grow with the size of the SBOM.
 */
function computeScore(components, counts, quality) {
  const n = components.length || 1;
  const critical = components.filter(c => c.tier === 'CRITICAL').length;
  const high = components.filter(c => c.tier === 'HIGH').length;
  const unknown = components.filter(c => !c.declaration.resolved).length;
  const tainted = components.filter(c => c.taintedSeverity === 'CRITICAL').length;

  const density = Math.min(1, (critical * 1.0 + high * 0.45 + unknown * 0.7 + tainted * 0.8) / n);
  const blockerDensity = Math.min(1, (counts.CRITICAL + counts.HIGH * 0.4) / Math.max(4, n * 0.25));
  const qualityPenalty = (100 - quality.score) / 100;

  const value = Math.round(100 * (0.5 * density + 0.3 * blockerDensity + 0.2 * qualityPenalty));
  const band = value >= 70 ? 'CRITICAL' : value >= 45 ? 'HIGH' : value >= 20 ? 'MEDIUM' : 'LOW';
  return { value, band, parts: { density: +density.toFixed(3), blockerDensity: +blockerDensity.toFixed(3), qualityPenalty: +qualityPenalty.toFixed(3) } };
}
