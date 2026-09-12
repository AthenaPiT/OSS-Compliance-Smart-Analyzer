/**
 * diff.js - Compare two SBOM milestones.
 *
 * `diffSboms(baseline, current)` where baseline is the older release.
 * Everything is keyed by component identity (purl without version, else name), so a
 * component keeps its identity across a version bump.
 */

import { TIERS } from './license-db.js';

const norm = s => String(s ?? '').trim().toLowerCase();

/** Stable identity across releases - purl without version, otherwise the name. */
export function identityKey(c) {
  if (c.purl) {
    const p = String(c.purl);
    const at = p.lastIndexOf('@');
    return at > 0 ? p.slice(0, at) : p;
  }
  return 'name:' + norm(c.name);
}

const findingKey = f => `${f.rule}|${norm(f.component)}|${norm(f.title)}`;

export function diffSboms(baseline, current) {
  const a = new Map(baseline.components.map(c => [identityKey(c), c]));
  const b = new Map(current.components.map(c => [identityKey(c), c]));

  const added = [], removed = [], versionChanged = [], licenseChanged = [];

  for (const [k, cb] of b) {
    const ca = a.get(k);
    if (!ca) { added.push(cb); continue; }
    if (norm(ca.version) !== norm(cb.version)) {
      versionChanged.push({ component: cb, from: ca.version, to: cb.version });
    }
    if (norm(ca.effectiveLicense) !== norm(cb.effectiveLicense)) {
      licenseChanged.push({
        component: cb,
        from: ca.effectiveLicense || 'NOASSERTION', fromTier: ca.tier,
        to: cb.effectiveLicense || 'NOASSERTION', toTier: cb.tier,
        escalated: TIERS[cb.tier].rank > TIERS[ca.tier].rank
      });
    }
  }
  for (const [k, ca] of a) if (!b.has(k)) removed.push(ca);

  // Licenses that moved from unresolved -> resolved (and the reverse).
  const resolvedNow = [], regressed = [];
  for (const [k, cb] of b) {
    const ca = a.get(k);
    if (!ca) continue;
    if (!ca.declaration.resolved && cb.declaration.resolved) resolvedNow.push(cb);
    if (ca.declaration.resolved && !cb.declaration.resolved) regressed.push(cb);
  }

  // Copyleft that is new to this milestone.
  const newCopyleft = added.filter(c => c.tier === 'CRITICAL' || c.tier === 'HIGH')
    .concat(licenseChanged.filter(l => l.escalated && (l.toTier === 'CRITICAL' || l.toTier === 'HIGH'))
      .map(l => l.component));
  const goneCopyleft = removed.filter(c => c.tier === 'CRITICAL' || c.tier === 'HIGH');

  const aFind = new Map(baseline.findings.map(f => [findingKey(f), f]));
  const bFind = new Map(current.findings.map(f => [findingKey(f), f]));
  const newFindings = [...bFind].filter(([k]) => !aFind.has(k)).map(([, f]) => f);
  const fixedFindings = [...aFind].filter(([k]) => !bFind.has(k)).map(([, f]) => f);

  const severityRank = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
  newFindings.sort((x, y) => (severityRank[y.severity] ?? 0) - (severityRank[x.severity] ?? 0));

  return {
    baseline: { name: baseline.meta.name, created: baseline.meta.created, score: baseline.score },
    current: { name: current.meta.name, created: current.meta.created, score: current.score },
    added, removed, versionChanged, licenseChanged,
    resolvedNow, regressed,
    newCopyleft, goneCopyleft,
    newFindings, fixedFindings,
    riskDelta: current.score.value - baseline.score.value,
    qualityDelta: current.quality.score - baseline.quality.score,
    counts: {
      added: added.length, removed: removed.length,
      versionChanged: versionChanged.length, licenseChanged: licenseChanged.length,
      newFindings: newFindings.length, fixedFindings: fixedFindings.length,
      newCritical: newFindings.filter(f => f.severity === 'CRITICAL').length,
      newHigh: newFindings.filter(f => f.severity === 'HIGH').length
    }
  };
}

/** Short human-readable verdict used by the CLI gate and the UI badge. */
export function diffVerdict(d) {
  if (d.counts.newCritical > 0) return { level: 'CRITICAL', text: `${d.counts.newCritical} new critical finding(s)` };
  if (d.counts.newHigh > 0) return { level: 'HIGH', text: `${d.counts.newHigh} new high finding(s)` };
  if (d.counts.newFindings > 0) return { level: 'MEDIUM', text: `${d.counts.newFindings} new finding(s)` };
  if (d.counts.licenseChanged > 0) return { level: 'MEDIUM', text: `${d.counts.licenseChanged} license change(s)` };
  return { level: 'LOW', text: 'no new compliance findings' };
}
