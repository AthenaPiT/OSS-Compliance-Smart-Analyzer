/**
 * license-db.js
 * SPDX license knowledge base for copyleft / OSS compliance risk assessment.
 *
 * IMPORTANT: This is an ENGINEERING TRIAGE model. It is not legal advice.
 * Every CRITICAL / HIGH finding must be confirmed by legal counsel before release.
 */

/* ---------------------------------------------------------------- tiers --- */

export const TIERS = {
  CRITICAL: {
    id: 'CRITICAL', rank: 5, label: 'Critical', color: '#ff4d4f',
    desc: 'Strong or network copyleft. Distribution triggers source disclosure of the derivative work.'
  },
  HIGH: {
    id: 'HIGH', rank: 4, label: 'High', color: '#ff9f43',
    desc: 'Weak / file-level copyleft, or a release blocker (unresolved license).'
  },
  MEDIUM: {
    id: 'MEDIUM', rank: 3, label: 'Medium', color: '#ffd166',
    desc: 'Conditional terms (advertising, non-commercial, ambiguous) that need review.'
  },
  LOW: {
    id: 'LOW', rank: 2, label: 'Low', color: '#2ecc71',
    desc: 'Permissive. Mainly notice and attribution obligations.'
  },
  UNKNOWN: {
    id: 'UNKNOWN', rank: 3.5, label: 'Unknown', color: '#8b9bb4',
    desc: 'Unresolved / custom license. Treated as a release blocker until triaged.'
  }
};

/* ---------------------------------------------------------- obligations --- */

export const OBLIGATIONS = {
  'notice': 'Include the copyright notice and a copy of the license text in the distribution',
  'state-changes': 'State that the component was modified, and the date of modification',
  'source-full': 'Provide complete corresponding source of the derivative work under the same license',
  'source-modified': 'Provide source of any modifications made to the licensed component',
  'relinking': 'Provide object files / a mechanism letting the recipient relink against a modified library',
  'network-source': 'Offer source to users who interact with the software over a network',
  'install-info': 'Provide installation information (keys, credentials) so modified firmware can be installed (GPL-3 anti-tivoization)',
  'patent': 'Include the patent grant and patent-termination notice',
  'no-endorsement': 'Do not use contributor or organisation names for endorsement',
  'advertising': 'Include an acknowledgement in advertising materials',
  'non-commercial': 'Non-commercial use only - NOT approved for commercial distribution'
};

/* ------------------------------------------------------------ license rules --- */
/* Longest-prefix matching. `match` is compared case-insensitively.          */

const STRONG_COPYLEFT_OBL = ['notice', 'state-changes', 'source-full'];
const GPL3_OBL = ['notice', 'state-changes', 'source-full', 'install-info', 'patent'];

export const LICENSE_RULES = [
  // --- Network / strong copyleft -------------------------------------------
  { match: 'agpl-', tier: 'CRITICAL', cat: 'network-copyleft', obl: ['notice', 'state-changes', 'source-full', 'network-source', 'patent'],
    note: 'AGPL extends copyleft to network interaction. Any telematics / backend service built on it must offer its source to users.' },
  { match: 'sspl-', tier: 'CRITICAL', cat: 'network-copyleft', obl: ['notice', 'source-full', 'network-source'],
    note: 'SSPL is not OSI-approved. Copyleft scope is unusually broad (whole service). Avoid in OEM shipments.' },
  { match: 'osl-', tier: 'CRITICAL', cat: 'strong-copyleft', obl: ['notice', 'source-full'],
    note: 'OSL treats external deployment as distribution.' },
  { match: 'cpal-', tier: 'CRITICAL', cat: 'strong-copyleft', obl: ['notice', 'source-full'] },
  { match: 'eupl-', tier: 'CRITICAL', cat: 'strong-copyleft', obl: ['notice', 'source-full', 'state-changes'],
    note: 'EUPL copyleft scope depends on the linked national law. Confirm the governing jurisdiction.' },
  { match: 'rpl-', tier: 'CRITICAL', cat: 'network-copyleft', obl: ['notice', 'source-full', 'network-source'] },
  { match: 'sleepycat', tier: 'CRITICAL', cat: 'strong-copyleft', obl: ['notice', 'source-full'],
    note: 'Sleepycat (Berkeley DB) is a strong copyleft license, often missed by scanners.' },

  // --- GPL family ----------------------------------------------------------
  { match: 'gpl-3.0', tier: 'CRITICAL', cat: 'strong-copyleft', obl: GPL3_OBL,
    note: 'GPL-3 adds anti-tivoization (installation information). Directly relevant to signed ECU firmware.' },
  { match: 'gpl-2.0', tier: 'CRITICAL', cat: 'strong-copyleft', obl: STRONG_COPYLEFT_OBL,
    note: 'GPL-2 has no explicit anti-tivoization clause but is incompatible with Apache-2.0.' },
  { match: 'gpl-1.0', tier: 'CRITICAL', cat: 'strong-copyleft', obl: STRONG_COPYLEFT_OBL },

  // --- Weak copyleft -------------------------------------------------------
  { match: 'lgpl-3.0', tier: 'HIGH', cat: 'weak-copyleft',
    obl: ['notice', 'state-changes', 'source-modified', 'relinking'],
    note: 'LGPL keeps application code free, but static linking requires a relinking mechanism (object files or a shared library).' },
  { match: 'lgpl-2.', tier: 'HIGH', cat: 'weak-copyleft',
    obl: ['notice', 'state-changes', 'source-modified', 'relinking'],
    note: 'In automotive monolithic firmware, LGPL static linking is the most common compliance gap.' },
  { match: 'ms-rl', tier: 'HIGH', cat: 'weak-copyleft', obl: ['notice', 'source-modified'] },

  // --- File-level copyleft -------------------------------------------------
  { match: 'mpl-', tier: 'HIGH', cat: 'file-copyleft',
    obl: ['notice', 'source-modified'],
    note: 'MPL copyleft is per-file. Modified MPL files must be published; newly added files may stay closed if kept separate.' },
  { match: 'epl-', tier: 'HIGH', cat: 'file-copyleft', obl: ['notice', 'source-modified', 'patent'],
    note: 'EPL is incompatible with GPL. Do not combine EPL and GPL code in one executable.' },
  { match: 'cpl-', tier: 'HIGH', cat: 'file-copyleft', obl: ['notice', 'source-modified', 'patent'] },
  { match: 'cddl-', tier: 'HIGH', cat: 'file-copyleft', obl: ['notice', 'source-modified'],
    note: 'CDDL is incompatible with GPL. Do not combine CDDL and GPL code in one executable.' },

  // --- Conditional / review-needed ----------------------------------------
  { match: 'cc-by-sa-', tier: 'HIGH', cat: 'share-alike', obl: ['notice', 'source-full'],
    note: 'Share-alike on documentation / assets can still contaminate a delivered bundle.' },
  { match: 'cc-by-nc-', tier: 'MEDIUM', cat: 'non-commercial', obl: ['notice', 'non-commercial', 'no-endorsement'],
    note: 'Non-commercial restriction. Not open source, not approved for a production vehicle.' },
  { match: 'cc-by-nd-', tier: 'MEDIUM', cat: 'no-derivatives', obl: ['notice', 'no-endorsement'],
    note: 'No-derivatives restriction blocks modification.' },
  { match: 'bsd-4-clause', tier: 'MEDIUM', cat: 'conditional', obl: ['notice', 'advertising'],
    note: 'Advertising clause is rarely acceptable to OEM legal. Prefer BSD-3-Clause.' },
  { match: 'apache-1.1', tier: 'MEDIUM', cat: 'conditional', obl: ['notice', 'advertising', 'no-endorsement'] },
  { match: 'openssl', tier: 'MEDIUM', cat: 'conditional', obl: ['notice', 'advertising'],
    note: 'Legacy OpenSSL license contains an advertising clause. OpenSSL 3.x is Apache-2.0 - verify the version.' },
  { match: 'artistic-1.0', tier: 'MEDIUM', cat: 'ambiguous', obl: ['notice', 'state-changes'],
    note: 'Artistic-1.0 is ambiguous and not GPL-compatible. Prefer Artistic-2.0.' },
  { match: 'json', tier: 'MEDIUM', cat: 'conditional', obl: ['notice'],
    note: 'JSON License adds "used for good, not evil" - unacceptable to many OEM legal teams.' },

  // --- Permissive / low ----------------------------------------------------
  { match: 'apache-2.0', tier: 'LOW', cat: 'permissive', obl: ['notice', 'state-changes', 'patent'] },
  { match: 'mit', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'isc', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'bsd-3-clause', tier: 'LOW', cat: 'permissive', obl: ['notice', 'no-endorsement'] },
  { match: 'bsd-2-clause', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: '0bsd', tier: 'LOW', cat: 'public-domain', obl: [] },
  { match: 'bsl-1.0', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'zlib', tier: 'LOW', cat: 'permissive', obl: ['notice'],
    note: 'Do not misrepresent the origin of the software.' },
  { match: 'libpng', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'icu', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'unicode-dfs-', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'python-2.0', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'psf-', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'ruby', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'ncsa', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'upl-1.0', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'ecl-', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'afl-', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'curl', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'x11', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'tcl', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'w3c', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'info-zip', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'postgresql', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'ms-pl', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'artistic-2.0', tier: 'LOW', cat: 'permissive', obl: ['notice'] },

  // --- Public domain -------------------------------------------------------
  { match: 'blessing', tier: 'LOW', cat: 'public-domain', obl: [], note: 'SQLite blessing - public domain dedication.' },
  { match: 'ftl', tier: 'LOW', cat: 'permissive', obl: ['notice'] },
  { match: 'cc0-1.0', tier: 'LOW', cat: 'public-domain', obl: [] },
  { match: 'unlicense', tier: 'LOW', cat: 'public-domain', obl: [] },
  { match: 'wtfpl', tier: 'LOW', cat: 'public-domain', obl: [] },

  // --- Proprietary / closed ------------------------------------------------
  { match: 'licenseRef-proprietary', tier: 'UNKNOWN', cat: 'proprietary', obl: [],
    note: 'Proprietary component. Any copyleft dependency statically linked into it creates an obligation on this component.' },
  { match: 'proprietary', tier: 'UNKNOWN', cat: 'proprietary', obl: [] }
];

/* Exceptions that relax copyleft, mainly for static linking.
 * Highly relevant in automotive, where firmware is usually statically linked. */
const LINKING_EXCEPTIONS = {
  'classpath-exception-2.0': { relax: 1, note: 'Classpath exception: linking does not impose GPL on the application.' },
  'classpath-exception': { relax: 1, note: 'Classpath exception: linking does not impose GPL on the application.' },
  'u-boot-exception-2.0': { relax: 1, note: 'U-Boot exception: static linking of GPL-2.0+ U-Boot into firmware is permitted.' },
  'gcc-exception-3.1': { relax: 1, note: 'GCC runtime library exception.' },
  'gcc-exception-2.0': { relax: 1, note: 'GCC runtime library exception.' },
  'autoconf-exception-2.0': { relax: 1, note: 'Autoconf configure-output exception.' },
  'autoconf-exception-3.0': { relax: 1, note: 'Autoconf configure-output exception.' },
  'bison-exception-2.2': { relax: 1, note: 'Bison parser-skeleton exception.' },
  'font-exception-2.0': { relax: 1, note: 'Font exception: documents using the font are not covered.' },
  'llvm-exception': { relax: 1, note: 'LLVM exception: relinking against modified LLVM is preserved.' },
  'qt-gpl-exception-1.0': { relax: 1, note: 'Qt GPL exception.' },
  'linux-syscall-note': { relax: 0, note: 'Syscall note: user-space programs calling the kernel are not derivative works.' },
  'swift-exception': { relax: 1, note: 'Swift exception.' },
  'libtool-exception': { relax: 1, note: 'Libtool exception.' }
};

/* Known license incompatibility pairs. Heuristic, coarse-grained by family. */
const COMPAT = [
  { a: 'gpl-2.0', b: 'apache-2.0', sev: 'HIGH', why: 'Apache-2.0 patent/indemnity terms are additional restrictions under GPL-2.0.' },
  { a: 'gpl-2.0', b: 'gpl-3.0', sev: 'HIGH', why: 'GPL-2.0-only and GPL-3.0 are mutually incompatible.' },
  { a: 'gpl-2.0', b: 'lgpl-3.0', sev: 'HIGH', why: 'LGPL-3.0 requires GPL-3.0, which is incompatible with GPL-2.0-only.' },
  { a: 'gpl-2.0', b: 'epl-', sev: 'HIGH', why: 'EPL and GPL are mutually incompatible.' },
  { a: 'gpl-2.0', b: 'cddl-', sev: 'HIGH', why: 'CDDL and GPL are mutually incompatible.' },
  { a: 'gpl-2.0', b: 'mpl-', sev: 'MEDIUM', why: 'MPL-2.0 offers GPL-2.0 as a secondary license, but combination still needs review.' },
  { a: 'agpl-', b: 'gpl-2.0', sev: 'HIGH', why: 'AGPL-3.0 and GPL-2.0-only are mutually incompatible.' },
  { a: 'agpl-', b: 'apache-2.0', sev: 'MEDIUM', why: 'AGPL-3.0 and Apache-2.0 are generally compatible, but the combined work becomes AGPL.' },
  { a: 'epl-', b: 'cddl-', sev: 'MEDIUM', why: 'EPL and CDDL are both file-level copyleft but not cross-compatible.' },
  { a: 'cc-by-nc-', b: 'apache-2.0', sev: 'HIGH', why: 'Non-commercial terms cannot be combined with commercial licenses.' },
  { a: 'cc-by-nc-', b: 'mit', sev: 'HIGH', why: 'Non-commercial terms cannot be combined with commercial licenses.' },
  { a: 'cc-by-sa-', b: 'apache-2.0', sev: 'MEDIUM', why: 'Share-alike propagates to the combined work.' }
];

const COPYLEFT_TEXT_HINTS = [
  { re: /\bagpl\b|affero/i, tier: 'CRITICAL', hint: 'Text references AGPL / Affero.' },
  { re: /\bgnu\s+general\s+public\s+licen[cs]e\b/i, tier: 'CRITICAL', hint: 'Text references the GNU GPL.' },
  { re: /\bgnu\s+(lesser|library)\s+general\s+public\s+licen[cs]e\b/i, tier: 'HIGH', hint: 'Text references the LGPL.' },
  { re: /\bgnu\s+free\s+documentation\b|\bgfdl\b/i, tier: 'MEDIUM', hint: 'Text references the GFDL.' },
  { re: /\bmozilla\s+public\s+licen[cs]e\b/i, tier: 'HIGH', hint: 'Text references the MPL.' },
  { re: /\beclipse\s+public\s+licen[cs]e\b/i, tier: 'HIGH', hint: 'Text references the EPL.' },
  { re: /\bnon-?commercial\b/i, tier: 'MEDIUM', hint: 'Text contains a non-commercial restriction.' }
];

/* ------------------------------------------------------------- helpers --- */

function normalize(id) {
  if (id == null) return '';
  let s = String(id).trim();
  if (s.endsWith('+')) s = s.slice(0, -1) + '-or-later';
  return s;
}

const CLASSIFY_CACHE = new Map();

/**
 * Classify a single SPDX license id (no operators).
 * @returns {{id:string, tier:string, rank:number, category:string, obligations:string[], note?:string, resolved:boolean}}
 */
export function classifyLicense(rawId) {
  const id = normalize(rawId);
  const key = id.toLowerCase();
  if (CLASSIFY_CACHE.has(key)) return { ...CLASSIFY_CACHE.get(key), id };

  let out;
  if (!id || key === 'noassertion' || key === 'none' || key === 'n/a') {
    out = { tier: 'UNKNOWN', rank: TIERS.UNKNOWN.rank, category: 'unknown', obligations: [], resolved: false,
            note: 'No license asserted. Must be resolved before release.' };
  } else if (key.startsWith('licenseref-')) {
    out = { tier: 'UNKNOWN', category: 'custom-ref', obligations: [], resolved: false,
            note: 'Custom license reference. Inspect hasExtractedLicensingInfos for the actual terms.' };
  } else {
    const rule = LICENSE_RULES
      .filter(r => key.startsWith(r.match))
      .sort((a, b) => b.match.length - a.match.length)[0];
    if (rule) {
      out = { tier: rule.tier, category: rule.cat, obligations: rule.obl || [], resolved: true, note: rule.note };
    } else {
      out = { tier: 'UNKNOWN', category: 'unrecognised', obligations: [], resolved: false,
              note: 'License id not in the local knowledge base. Enrich from SPDX/ClearlyDefined or triage manually.' };
    }
  }
  out.rank = TIERS[out.tier].rank;
  CLASSIFY_CACHE.set(key, out);
  return { ...out, id };
}

/** Escalate or relax a classification based on a WITH <exception> modifier. */
export function applyException(cls, exceptionId) {
  if (!exceptionId) return cls;
  const key = normalize(exceptionId).toLowerCase();
  const entry = Object.entries(LINKING_EXCEPTIONS)
    .filter(([k]) => key.startsWith(k))
    .sort((a, b) => b[0].length - a[0].length)[0];
  if (!entry) return cls;
  const [, ex] = entry;
  if (!ex.relax) return { ...cls, note: [cls.note, ex.note].filter(Boolean).join(' ') };
  // Relaxation ladder deliberately excludes UNKNOWN (it is not a copyleft strength).
  const ladder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const idx = Math.max(0, (ladder.indexOf(cls.tier) < 0 ? ladder.length - 1 : ladder.indexOf(cls.tier)) - ex.relax);
  const tier = ladder[idx];
  return {
    ...cls, tier, rank: TIERS[tier].rank,
    category: cls.category === 'strong-copyleft' ? 'copyleft-with-exception' : cls.category,
    linkingException: exceptionId,
    note: [cls.note, ex.note].filter(Boolean).join(' ')
  };
}

/** Scan custom license text for copyleft indicators. */
export function inspectLicenseText(text) {
  if (!text) return null;
  for (const h of COPYLEFT_TEXT_HINTS) {
    if (h.re.test(text)) return { tier: h.tier, hint: h.hint };
  }
  return null;
}

/* ------------------------------------------------- SPDX expression engine --- */

/**
 * Parse an SPDX license expression into a tree.
 * Grammar: expr := term (OR term)* ; term := factor (AND factor)* ;
 *          factor := '(' expr ')' | id ('+' | WITH id)?
 */
export function parseExpression(input) {
  const src = String(input || '').trim();
  if (!src) return null;
  const tokens = src.match(/\(|\)|[^\s()]+/g) || [];
  let pos = 0;

  const peek = () => tokens[pos];
  const isOp = t => t && /^(and|or|with)$/i.test(t);

  function parseExpr() {
    let node = parseTerm();
    while (peek() && /^or$/i.test(peek())) { pos++; const r = parseTerm(); node = { type: 'OR', left: node, right: r }; }
    return node;
  }
  function parseTerm() {
    let node = parseFactor();
    while (peek() && /^and$/i.test(peek())) { pos++; const r = parseFactor(); node = { type: 'AND', left: node, right: r }; }
    return node;
  }
  function parseFactor() {
    const t = tokens[pos++];
    if (t === '(') { const n = parseExpr(); pos++; return n; }
    if (t === undefined) return null;
    if (isOp(t)) return parseFactor();
    let node = { type: 'LICENSE', id: normalize(t) };
    if (peek() && /^with$/i.test(peek())) { pos++; node.exception = normalize(tokens[pos++]); }
    return node;
  }

  try {
    const ast = parseExpr();
    return ast;
  } catch (e) {
    return { type: 'LICENSE', id: src };
  }
}

function walk(ast, fn) {
  if (!ast) return;
  fn(ast);
  if (ast.left) walk(ast.left, fn);
  if (ast.right) walk(ast.right, fn);
}

/**
 * Evaluate an SPDX expression into a compliance verdict.
 * AND -> worst case (all obligations apply).
 * OR  -> best case (you may elect the most favourable), but the election must be documented.
 */
export function evaluateExpression(input) {
  const raw = String(input || '').trim();
  if (!raw || /^(noassertion|none)$/i.test(raw)) {
    return { raw, tier: 'UNKNOWN', rank: TIERS.UNKNOWN.rank, licenses: [], obligations: [],
             notes: ['No license asserted.'], multi: false, resolved: false, unresolved: true, worstTier: 'UNKNOWN' };
  }
  const ast = parseExpression(raw);
  const licenses = [];
  const notes = [];
  let hasOr = false, hasAnd = false, unresolved = false;

  walk(ast, n => {
    if (n.type === 'OR') hasOr = true;
    if (n.type === 'AND') hasAnd = true;
    if (n.type === 'LICENSE') {
      const cls = applyException(classifyLicense(n.id), n.exception);
      if (!cls.resolved) unresolved = true;
      licenses.push(cls);
    }
  });

  if (!licenses.length) {
    const cls = classifyLicense(raw);
    licenses.push(cls);
    unresolved = !cls.resolved;
  }

  const ranks = licenses.map(l => l.rank);
  const best = Math.min(...ranks);
  const worst = Math.max(...ranks);
  const rank = hasOr && !hasAnd ? best : worst;
  const tier = Object.values(TIERS).find(t => t.rank === rank)?.id || 'UNKNOWN';

  let obligations = [...new Set(licenses.flatMap(l => l.obligations || []))];
  if (hasOr && !hasAnd) {
    const chosen = licenses.find(l => l.rank === best);
    obligations = [...new Set((chosen?.obligations || []))];
    notes.push(`Dual/multi-licensed (${licenses.map(l => l.id).join(' OR ')}). Elect "${chosen?.id}" and record the election in the compliance file.`);
  }
  if (hasAnd) notes.push('Expression contains AND: every listed license applies simultaneously.');
  if (unresolved) notes.push('At least one term could not be resolved - manual triage required.');
  licenses.filter(l => l.linkingException).forEach(l => notes.push(`${l.id} carries the ${l.linkingException} linking exception.`));

  return {
    raw, tier, rank, licenses, obligations, notes,
    multi: hasOr, unresolved,
    worstTier: Object.values(TIERS).find(t => t.rank === worst)?.id || 'UNKNOWN',
    category: licenses.find(l => l.rank === rank)?.category || 'unknown'
  };
}

/** Pairwise incompatibility check within one distributed unit. */
export function checkCompatibility(licenseIds) {
  const conflicts = [];
  const norm = [...new Set(licenseIds.map(l => normalize(l).toLowerCase()))]
    .filter(l => l && !/^(noassertion|none)$/.test(l) && !l.startsWith('licenseref-'));
  for (let i = 0; i < norm.length; i++) {
    for (let j = i + 1; j < norm.length; j++) {
      const a = norm[i], b = norm[j];
      for (const c of COMPAT) {
        const hit = (a.startsWith(c.a) && b.startsWith(c.b)) || (a.startsWith(c.b) && b.startsWith(c.a));
        if (hit) conflicts.push({ a, b, severity: c.sev, reason: c.why });
      }
    }
  }
  return conflicts;
}
