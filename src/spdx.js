/**
 * spdx.js - SPDX 2.x JSON parsing, dependency graph construction and SBOM quality checks.
 */

const DEPENDENCY_RELATIONS = new Set([
  'DEPENDS_ON', 'CONTAINS', 'HAS_PREREQUISITE', 'REQUIREMENT_DESCRIBED_BY'
]);
const LINK_RELATIONS = new Set(['STATIC_LINK', 'DYNAMIC_LINK']);
const DEV_RELATIONS = new Set([
  'DEV_DEPENDENCY_OF', 'BUILD_DEPENDENCY_OF', 'TEST_DEPENDENCY_OF',
  'OPTIONAL_DEPENDENCY_OF', 'PROVIDED_DEPENDENCY_OF'
]);

/** Parses an SPDX 2.x JSON document into a normalised model. */
export function parseSpdx(json) {
  const errors = [];
  const warnings = [];

  if (!json || typeof json !== 'object') throw new Error('SBOM is not a JSON object.');
  if (!json.packages && !json.Packages) throw new Error('No "packages" array found. Is this an SPDX JSON file?');

  const packages = (json.packages || json.Packages || []).map((p, i) => {
    const externalRefs = (p.externalRefs || p.externalRef || []).map(r => ({
      category: r.referenceCategory,
      type: r.referenceType,
      locator: r.referenceLocator,
      purl: /^purl-spec$/i.test(r.referenceType || '') ? (r.referenceLocator || null) : null
    }));

    return {
      index: i,
      spdxId: p.SPDXID || `SPDXRef-Package-${i}`,
      name: p.name || p.SPDXID || '(unnamed)',
      version: p.versionInfo || '',
      supplier: p.supplier || '',
      originator: p.originator || '',
      downloadLocation: p.downloadLocation || '',
      filesAnalyzed: p.filesAnalyzed !== false,
      copyright: p.copyrightText || '',
      licenseConcluded: p.licenseConcluded || '',
      licenseDeclared: p.licenseDeclared || '',
      licenseInfoFromFiles: p.licenseInfoFromFiles || [],
      licenseComments: p.licenseComments || '',
      checksums: (p.checksums || []).map(c => `${c.algorithm}:${c.checksumValue}`),
      externalRefs,
      purl: (externalRefs.find(e => e.purl) || {}).purl || null,
      homepage: p.homepage || '',
      primaryPurpose: p.primaryPurpose || '',
      comment: p.comment || '',
      raw: p
    };
  }).filter(p => {
    const drop = /^SPDXRef-(Document|File)-/.test(p.spdxId);
    return !drop;
  });

  const byId = new Map(packages.map(p => [p.spdxId, p]));

  const relationships = (json.relationships || []).map(r => ({
    from: r.spdxElementId,
    to: r.relatedSpdxElement,
    type: (r.relationshipType || '').toUpperCase(),
    comment: r.relationshipComment || ''
  })).filter(r => byId.has(r.from) && byId.has(r.to));

  const extractedLicenses = (json.hasExtractedLicensingInfos || []).map(l => ({
    id: l.licenseId, name: l.name || l.licenseId, text: l.extractedText || '',
    crossRefs: l.crossRefs || [], comment: l.comment || ''
  }));

  // Roots: documentDescribes, otherwise packages with no incoming dependency edge.
  const described = new Set(json.documentDescribes || []);
  let roots = packages.filter(p => described.has(p.spdxId)).map(p => p.spdxId);
  if (!roots.length) {
    const hasIncoming = new Set(
      relationships.filter(r => DEPENDENCY_RELATIONS.has(r.type) || LINK_RELATIONS.has(r.type))
        .map(r => r.to)
    );
    roots = packages.filter(p => !hasIncoming.has(p.spdxId)).map(p => p.spdxId);
    if (roots.length > 1) warnings.push(`${roots.length} candidate root packages detected (no documentDescribes).`);
  }
  if (!roots.length && packages.length) roots = [packages[0].spdxId];

  if (!json.creationInfo && !json.creationInfo === undefined) errors.push('Missing creationInfo.');

  return {
    meta: {
      spdxVersion: json.spdxVersion || 'unknown',
      dataLicense: json.dataLicense || '',
      name: json.name || '(unnamed SBOM)',
      documentNamespace: json.documentNamespace || '',
      creators: (json.creationInfo?.creators) || [],
      created: json.creationInfo?.created || '',
      comment: json.comment || ''
    },
    packages, byId, relationships, extractedLicenses, roots,
    files: (json.files || []).length,
    errors, warnings
  };
}

/**
 * Builds a directed dependency graph.
 * Edges are oriented parent -> child (parent depends on / contains child).
 * `linkage` is 'static' | 'dynamic' | 'unknown' | 'dev' | 'optional'.
 */
export function buildDependencyGraph(sbom) {
  const edges = [];
  const seen = new Set();

  for (const r of sbom.relationships) {
    const kind = classifyRelation(r.type);
    if (!kind) continue;
    const key = `${r.from}|${r.to}|${kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({
      source: r.from,
      target: r.to,
      type: r.type,
      linkage: kind.linkage,
      dev: kind.dev,
      optional: kind.optional
    });
  }

  // Deduplicate: prefer an explicit STATIC/DYNAMIC_LINK edge over a plain DEPENDS_ON.
  const byPair = new Map();
  for (const e of edges) {
    const k = `${e.source}->${e.target}`;
    const prev = byPair.get(k);
    if (!prev || (prev.linkage === 'unknown' && e.linkage !== 'unknown')) byPair.set(k, e);
  }
  const finalEdges = [...byPair.values()];

  const children = new Map();
  const parents = new Map();
  for (const e of finalEdges) {
    (children.get(e.source) || children.set(e.source, []).get(e.source)).push(e);
    (parents.get(e.target) || parents.set(e.target, []).get(e.target)).push(e);
  }

  return { edges: finalEdges, children, parents };
}

function classifyRelation(type) {
  if (type === 'STATIC_LINK') return { linkage: 'static', dev: false, optional: false };
  if (type === 'DYNAMIC_LINK') return { linkage: 'dynamic', dev: false, optional: false };
  if (type === 'DEPENDS_ON' || type === 'CONTAINS' || type === 'HAS_PREREQUISITE') {
    return { linkage: 'unknown', dev: false, optional: false };
  }
  if (type === 'DEV_DEPENDENCY_OF' || type === 'BUILD_DEPENDENCY_OF' || type === 'TEST_DEPENDENCY_OF') {
    return { linkage: 'unknown', dev: true, optional: false };
  }
  if (type === 'OPTIONAL_DEPENDENCY_OF' || type === 'PROVIDED_DEPENDENCY_OF') {
    return { linkage: 'unknown', dev: false, optional: true };
  }
  return null;
}

/**
 * NTIA minimum elements + practical audit completeness checks.
 * Reference: NTIA "The Minimum Elements For a Software Bill of Materials" (2021).
 */
export function checkSbomQuality(sbom) {
  const pkgs = sbom.packages;
  const total = pkgs.length || 1;
  const missing = f => pkgs.filter(f).length;

  const noSupplier = missing(p => !p.supplier || /NOASSERTION/i.test(p.supplier));
  const noVersion = missing(p => !p.version);
  const noPurl = missing(p => !p.purl);
  const noChecksum = missing(p => !p.checksums.length);
  const noDownload = missing(p => !p.downloadLocation || /NOASSERTION/i.test(p.downloadLocation));
  const noCopyright = missing(p => !p.copyright || /NOASSERTION/i.test(p.copyright));
  const notAnalyzed = missing(p => !p.filesAnalyzed);

  const checks = [
    { id: 'NTIA-1', label: 'Supplier name', ok: noSupplier === 0,
      detail: `${noSupplier} / ${total} components missing a supplier` },
    { id: 'NTIA-2', label: 'Component name', ok: pkgs.every(p => p.name && p.name !== '(unnamed)'),
      detail: `${missing(p => !p.name)} / ${total} components missing a name` },
    { id: 'NTIA-3', label: 'Version identifier', ok: noVersion === 0,
      detail: `${noVersion} / ${total} components missing a version` },
    { id: 'NTIA-4', label: 'Unique identifier (purl)', ok: noPurl === 0,
      detail: `${noPurl} / ${total} components missing a package URL` },
    { id: 'NTIA-5', label: 'Dependency relationship', ok: sbom.relationships.length > 0,
      detail: `${sbom.relationships.length} relationships recorded` },
    { id: 'NTIA-6', label: 'SBOM author', ok: sbom.meta.creators.length > 0,
      detail: sbom.meta.creators.length ? sbom.meta.creators.join(', ') : 'no creationInfo.creators' },
    { id: 'NTIA-7', label: 'Timestamp', ok: !!sbom.meta.created,
      detail: sbom.meta.created || 'no creationInfo.created' },
    { id: 'AUD-1', label: 'Checksums', ok: noChecksum === 0,
      detail: `${noChecksum} / ${total} components missing a checksum` },
    { id: 'AUD-2', label: 'Download location', ok: noDownload === 0,
      detail: `${noDownload} / ${total} components missing a resolved download location` },
    { id: 'AUD-3', label: 'Copyright text', ok: noCopyright === 0,
      detail: `${noCopyright} / ${total} components missing copyright text` },
    { id: 'AUD-4', label: 'Files analysed', ok: notAnalyzed === 0,
      detail: `${notAnalyzed} / ${total} components marked filesAnalyzed=false` },
    { id: 'AUD-5', label: 'Linkage declared', ok: sbom.relationships.some(r => LINK_RELATIONS.has(r.type)),
      detail: sbom.relationships.filter(r => LINK_RELATIONS.has(r.type)).length +
              ' explicit STATIC_LINK / DYNAMIC_LINK relations (critical for LGPL assessment)' }
  ];

  const passed = checks.filter(c => c.ok).length;
  return { checks, passed, total: checks.length, score: Math.round((passed / checks.length) * 100) };
}
