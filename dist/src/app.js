/**
 * app.js - UI wiring for the OSS Compliance Smart Analyzer.
 */

import { parseSpdx } from './spdx.js';
import { analyze } from './risk-engine.js';
import { TIERS, OBLIGATIONS } from './license-db.js';
import { diffSboms, diffVerdict } from './diff.js';
import { createGraph } from './graph.js';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

let state = { sbom: null, result: null, graph: null, selected: null, previous: null, previousName: null };

/* ------------------------------------------------------------- loading --- */

$('#btn-pick').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', e => { const f = e.target.files[0]; if (f) loadFile(f); });
$('#btn-sample').addEventListener('click', async () => {
  render(await fetchJson('samples/sample-ivisystem.spdx.json'), 'sample-ivisystem.spdx.json');
});
$('#btn-sample-diff').addEventListener('click', async () => {
  render(await fetchJson('samples/sample-ivisystem.spdx.json'), 'sample-ivisystem.spdx.json');
  state.previous = analyze(parseSpdx(await fetchJson('samples/sample-ivisystem-4.1.0.spdx.json')));
  state.previousName = 'sample-ivisystem-4.1.0.spdx.json';
  renderDiff();
});

async function fetchJson(url) {
  const res = await fetch(url);
  return await res.json();
}
$('#btn-new').addEventListener('click', () => {
  $('#dashboard').hidden = true;
  $('#dropzone').hidden = false;
  state.graph?.stop();
  state.previous = null;
  $('#diff-card').innerHTML = '';
  ['#btn-export-json', '#btn-export-csv', '#btn-compare'].forEach(s => $(s).hidden = true);
});

$('#btn-compare').addEventListener('click', () => $('#file2').click());
$('#file2').addEventListener('change', e => {
  const f = e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      state.previous = analyze(parseSpdx(JSON.parse(r.result)));
      state.previousName = f.name;
      renderDiff();
    } catch (err) { alert('Could not parse the baseline SBOM: ' + err.message); }
  };
  r.readAsText(f);
});

const dz = $('#dropzone');
['dragenter', 'dragover'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove('over'); }));
dz.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) loadFile(f); });

function loadFile(file) {
  const r = new FileReader();
  r.onload = () => {
    try { render(JSON.parse(r.result), file.name); }
    catch (err) { alert('Could not parse the file: ' + err.message); }
  };
  r.readAsText(file);
}

/* -------------------------------------------------------------- render --- */

function render(json, filename) {
  const sbom = parseSpdx(json);
  const result = analyze(sbom);
  state = { sbom, result, graph: null, selected: null };

  $('#dropzone').hidden = true;
  $('#dashboard').hidden = false;
  ['#btn-export-json', '#btn-export-csv', '#btn-compare'].forEach(s => $(s).hidden = false);
  $('#hdr-sub').textContent =
    `${sbom.meta.name} - ${filename} - SPDX ${sbom.meta.spdxVersion} - ${sbom.packages.length} components`;
  $('#g-search').value = '';
  $('#f-search').value = '';
  $('#c-search').value = '';

  renderKpis(result, sbom);
  renderLicenseChart(result);
  renderQuality(result.quality);
  renderFindings(result);
  renderComponents(result);
  renderGraph(result);
  renderDiff();
}

function renderDiff() {
  const box = $('#diff-card');
  if (!state.previous || !state.result) { box.innerHTML = ''; return; }
  const d = diffSboms(state.previous, state.result);
  const v = diffVerdict(d);
  const sign = n => (n >= 0 ? '+' : '') + n;

  const rows = [
    ['New components', d.counts.added, d.added.map(c => `${c.name} ${c.version || ''} — ${c.effectiveLicense || 'NOASSERTION'} <span class="badge ${c.tier}">${c.tier}</span>`)],
    ['Removed components', d.counts.removed, d.removed.map(c => `${c.name} ${c.version || ''}`)],
    ['License changes', d.counts.licenseChanged, d.licenseChanged.map(l =>
      `${l.component.name}: "${l.from}" → "${l.to}" ${l.escalated ? '<span class="badge HIGH">escalated</span>' : '<span class="badge LOW">ok</span>'}`)],
    ['Version changes', d.counts.versionChanged, d.versionChanged.map(x => `${x.component.name}: ${x.from || '-'} → ${x.to || '-'}`)],
    ['New copyleft', d.newCopyleft.length, d.newCopyleft.map(c => `${c.name} — ${c.effectiveLicense} <span class="badge ${c.tier}">${c.tier}</span>`)],
    ['Regressions to unresolved', d.regressed.length, d.regressed.map(c => `${c.name} — ${c.effectiveLicense || 'NOASSERTION'}`)],
    ['New findings', d.counts.newFindings, d.newFindings.slice(0, 12).map(f => `<span class="badge ${f.severity}">${f.severity}</span> ${esc(f.rule)} ${esc(f.title)}`)],
    ['Closed findings', d.counts.fixedFindings, d.fixedFindings.slice(0, 12).map(f => `<span class="badge ${f.severity}">${f.severity}</span> ${esc(f.title)}`)]
  ];

  box.innerHTML = `
    <div class="card" style="margin-bottom:14px;border-left:3px solid ${
      v.level === 'CRITICAL' ? 'var(--critical)' : v.level === 'HIGH' ? 'var(--high)' :
      v.level === 'MEDIUM' ? 'var(--medium)' : 'var(--low)'}">
      <h2>Milestone diff <span class="tag">baseline ${esc(state.previousName)} (${esc(state.previous.meta.name)}) → current (${esc(state.result.meta.name)})</span></h2>
      <div style="display:flex;gap:18px;flex-wrap:wrap;align-items:baseline;margin-bottom:10px">
        <div><span class="badge ${v.level}">${v.level}</span> ${esc(v.text)}</div>
        <div class="muted">risk ${state.previous.score.value} → ${state.result.score.value} (${sign(d.riskDelta)})</div>
        <div class="muted">SBOM quality ${state.previous.quality.score}% → ${state.result.quality.score}% (${sign(d.qualityDelta)})</div>
      </div>
      <table><tbody>
        ${rows.map(([label, count, items]) => `
          <tr>
            <td style="width:180px">${label}</td>
            <td style="width:52px"><strong>${count}</strong></td>
            <td class="muted">${items.length ? items.join('<br/>') : '-'}</td>
          </tr>`).join('')}
      </tbody></table>
    </div>`;
}

function renderKpis(r, sbom) {
  const crit = r.components.filter(c => c.tier === 'CRITICAL');
  const high = r.components.filter(c => c.tier === 'HIGH');
  const unk = r.components.filter(c => !c.declaration.resolved);
  const tainted = r.components.filter(c => c.taintedSeverity === 'CRITICAL');
  const bandColor = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'ok' }[r.score.band];

  const cards = [
    { cls: bandColor, label: 'Risk score', value: r.score.value, sub: `band: ${r.score.band}` },
    { cls: 'crit', label: 'Critical copyleft', value: crit.length, sub: 'GPL / AGPL / OSL / EUPL' },
    { cls: 'high', label: 'High copyleft', value: high.length, sub: 'LGPL / MPL / EPL / CDDL' },
    { cls: crit.length || unk.length ? 'crit' : 'ok', label: 'Release blockers', value: r.counts.CRITICAL + r.counts.HIGH, sub: `${unk.length} unresolved licenses` },
    { cls: 'high', label: 'Tainted components', value: tainted.length, sub: 'inherit copyleft transitively' },
    { cls: r.quality.score >= 80 ? 'ok' : r.quality.score >= 50 ? 'med' : 'high', label: 'SBOM quality', value: `${r.quality.score}%`, sub: `${r.quality.passed}/${r.quality.total} checks pass` }
  ];
  $('#kpis').innerHTML = cards.map(c => `
    <div class="kpi-card ${c.cls}">
      <div class="label">${c.label}</div>
      <div class="value">${esc(c.value)}</div>
      <div class="sub">${esc(c.sub)}</div>
    </div>`).join('');
}

function renderLicenseChart(r) {
  const stats = r.licenseStats.slice(0, 14);
  const max = Math.max(...stats.map(s => s.count), 1);
  $('#license-chart').innerHTML = stats.map(s => `
    <div class="bar-row" title="${esc(s.components.slice(0, 12).join(', '))}">
      <div class="name mono">${esc(s.id)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(s.count / max) * 100}%;background:${TIERS[s.tier].color}"></div></div>
      <div class="num">${s.count}</div>
    </div>`).join('') +
    (r.licenseStats.length > 14 ? `<p class="note">+${r.licenseStats.length - 14} further distinct license expressions</p>` : '');
}

function renderQuality(q) {
  $('#quality').innerHTML = `
    <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:10px">
      <div style="font-size:26px;font-weight:600">${q.score}%</div>
      <div class="muted">${q.passed} of ${q.total} checks satisfied</div>
    </div>
    <table><tbody>
      ${q.checks.map(c => `
        <tr>
          <td style="width:24px;color:${c.ok ? '#2ecc71' : '#ff9f43'}">${c.ok ? '&#10003;' : '!'}</td>
          <td style="width:52px" class="mono muted">${esc(c.id)}</td>
          <td>${esc(c.label)}</td>
          <td class="muted">${esc(c.detail)}</td>
        </tr>`).join('')}
    </tbody></table>`;
}

function renderFindings(r) {
  const sev = $('#f-sev').value;
  const q = $('#f-search').value.trim().toLowerCase();
  const rows = r.findings.filter(f =>
    (!sev || f.severity === sev) &&
    (!q || (f.title + f.component + f.detail).toLowerCase().includes(q)));

  $('#findings-count').textContent = `${r.findings.length} total, ${rows.length} shown`;
  $('#findings tbody').innerHTML = rows.map(f => `
    <tr>
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      <td class="mono muted">${esc(f.rule)}</td>
      <td>
        <div><strong>${esc(f.title)}</strong></div>
        <div class="muted">${esc(f.detail)}</div>
        <div class="muted"><span class="linkish" data-goto="${esc(f.componentId)}">show in graph &rarr;</span></div>
      </td>
      <td class="muted">${esc(f.obligation)}</td>
      <td class="muted">${esc(f.action)}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted">No findings for the current filter.</td></tr>';

  $('#findings tbody').querySelectorAll('[data-goto]').forEach(el =>
    el.addEventListener('click', () => {
      state.graph?.focus(el.dataset.goto);
      openDetail(el.dataset.goto);
      document.querySelector('#graph-wrap').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }));
}

function renderComponents(r) {
  const tier = $('#c-tier').value;
  const q = $('#c-search').value.trim().toLowerCase();
  const rows = r.components.filter(c =>
    (!tier || c.tier === tier) &&
    (!q || (c.name + c.effectiveLicense + (c.purl || '') + c.supplier).toLowerCase().includes(q)));

  $('#comp-count').textContent = `${r.components.length} components, ${rows.length} shown`;
  $('#components tbody').innerHTML = rows.map(c => `
    <tr>
      <td>
        <div class="linkish" data-goto="${esc(c.spdxId)}">${esc(c.name)}</div>
        <div class="muted mono">${esc(c.purl || c.spdxId)}</div>
      </td>
      <td class="mono">${esc(c.version || '-')}</td>
      <td class="mono">${esc(c.effectiveLicense || 'NOASSERTION')}
        <div class="muted">${esc(c.licenseSource)}</div></td>
      <td><span class="badge ${c.tier}">${c.tier}</span></td>
      <td class="muted">${c.taintedBy.length
        ? c.taintedBy.slice(0, 3).map(t => `${esc(t.name)} <span class="badge ${t.severity}">${t.linkKind || '?'}</span>`).join('<br/>')
        : '-'}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted">No components match.</td></tr>';

  $('#components tbody').querySelectorAll('[data-goto]').forEach(el =>
    el.addEventListener('click', () => { state.graph?.focus(el.dataset.goto); openDetail(el.dataset.goto); }));
}

/* --------------------------------------------------------------- graph --- */

function buildGraphModel(r) {
  const degree = new Map();
  for (const e of r.graph.edges) {
    degree.set(e.source, (degree.get(e.source) || 0) + 1);
    degree.set(e.target, (degree.get(e.target) || 0) + 1);
  }
  const nodes = r.components.map(c => ({
    id: c.spdxId,
    label: c.name,
    color: TIERS[c.tier].color,
    tier: c.tier,
    rank: c.rank,
    degree: degree.get(c.spdxId) || 0,
    isRoot: c.isRoot,
    taintedSeverity: c.taintedSeverity,
    license: c.effectiveLicense
  }));
  return { nodes, edges: r.graph.edges };
}

function renderGraph(r) {
  const model = buildGraphModel(r);
  const q = $('#g-search').value.trim().toLowerCase();
  const tier = $('#g-tier').value;
  const link = $('#g-link').value;

  let nodes = model.nodes;
  let edges = model.edges;
  const byId = new Map(r.components.map(c => [c.spdxId, c]));

  if (q) nodes = nodes.filter(n => (n.label + ' ' + (n.license || '')).toLowerCase().includes(q));
  if (tier === 'CRITICAL') nodes = nodes.filter(n => n.tier === 'CRITICAL');
  if (tier === 'HIGH') nodes = nodes.filter(n => n.tier === 'CRITICAL' || n.tier === 'HIGH');
  if (tier === 'UNKNOWN') nodes = nodes.filter(n => n.tier === 'UNKNOWN');
  if (link) edges = edges.filter(e => e.linkage === link);

  const keep = new Set(nodes.map(n => n.id));
  if (q || tier) edges = edges.filter(e => keep.has(e.source) && keep.has(e.target));

  state.graph?.stop();
  state.graph = createGraph($('#graph'), {
    nodes, edges,
    onSelect: d => openDetail(d.id)
  });
  $('#g-stat').textContent = `${nodes.length} nodes / ${edges.length} edges` +
    (state.graph.truncated ? ` (${state.graph.truncated} low-risk nodes hidden)` : '');
}

/* -------------------------------------------------------------- detail --- */

function openDetail(id) {
  const r = state.result;
  if (!r) return;
  const c = r.byId.get(id);
  if (!c) return;
  const parents = (r.graph.parents.get(id) || []).map(e => r.byId.get(e.source)).filter(Boolean);
  const children = (r.graph.children.get(id) || []).map(e => ({ c: r.byId.get(e.target), e })).filter(x => x.c);

  $('#detail-body').innerHTML = `
    <h2>${esc(c.name)}</h2>
    <div class="muted">${esc(c.version || 'no version')} &middot; <span class="badge ${c.tier}">${c.tier}</span></div>
    <dl>
      <dt>Effective license</dt>
      <dd class="mono">${esc(c.effectiveLicense || 'NOASSERTION')} <span class="muted">(${esc(c.licenseSource)})</span></dd>
      <dt>Declared / concluded</dt>
      <dd class="mono">declared: ${esc(c.licenseDeclared || '-')}<br/>concluded: ${esc(c.licenseConcluded || '-')}</dd>
      <dt>Supplier</dt><dd>${esc(c.supplier || '-')}</dd>
      <dt>Download</dt><dd class="mono">${esc(c.downloadLocation || '-')}</dd>
      <dt>purl</dt><dd class="mono">${esc(c.purl || '-')}</dd>
      <dt>Copyright</dt><dd>${esc(c.copyright || '-')}</dd>
      <dt>Obligations</dt>
      <dd>${(c.obligations || []).length
        ? '<ul style="margin:4px 0;padding-left:16px">' + c.obligations.map(o => `<li>${esc(OBLIGATIONS[o] || o)}</li>`).join('') + '</ul>'
        : '<span class="muted">none recorded</span>'}</dd>
      ${c.declaration.notes?.length ? `<dt>Notes</dt><dd class="muted">${c.declaration.notes.map(esc).join('<br/>')}</dd>` : ''}
      ${c.taintedBy.length ? `<dt>Copyleft inherited from</dt><dd>${
        c.taintedBy.map(t => `${esc(t.name)} <span class="badge ${t.severity}">${t.severity}</span> <span class="muted">(${t.linkKind || 'linkage n/a'}, ${t.hops} hop)</span>`).join('<br/>')
      }</dd>` : ''}
      <dt>Used by (${parents.length})</dt>
      <dd>${parents.slice(0, 20).map(p => `<span class="linkish" data-goto="${esc(p.spdxId)}">${esc(p.name)}</span>`).join('<br/>') || '-'}</dd>
      <dt>Depends on (${children.length})</dt>
      <dd>${children.slice(0, 30).map(({ c: ch, e }) =>
        `<span class="linkish" data-goto="${esc(ch.spdxId)}">${esc(ch.name)}</span> <span class="muted">${esc(e.linkage)}</span>`).join('<br/>') || '-'}</dd>
    </dl>`;

  $('#detail').classList.add('open');
  $('#detail-body').querySelectorAll('[data-goto]').forEach(el =>
    el.addEventListener('click', () => { openDetail(el.dataset.goto); state.graph?.focus(el.dataset.goto); }));
}

$('#detail-close').addEventListener('click', () => $('#detail').classList.remove('open'));

/* -------------------------------------------------------------- export --- */

$('#btn-export-json').addEventListener('click', () => {
  const r = state.result;
  const report = {
    tool: 'oss-compliance-analyzer', version: '0.1.0',
    generatedAt: new Date().toISOString(),
    document: r.meta,
    score: r.score,
    sbomQuality: r.quality,
    summary: {
      components: r.components.length,
      tierCounts: r.tierCounts,
      findings: r.counts,
      unresolvedLicenses: r.components.filter(c => !c.declaration.resolved).length
    },
    findings: r.findings,
    obligations: r.obligations.map(o => ({ id: o, text: OBLIGATIONS[o] || o })),
    components: r.components.map(c => ({
      name: c.name, version: c.version, purl: c.purl, spdxId: c.spdxId,
      supplier: c.supplier, license: c.effectiveLicense, licenseSource: c.licenseSource,
      tier: c.tier, copyleft: c.copyleft,
      inherited: c.taintedBy
    }))
  };
  download(JSON.stringify(report, null, 2), 'oss-compliance-report.json', 'application/json');
});

$('#btn-export-csv').addEventListener('click', () => {
  const r = state.result;
  const head = ['component', 'version', 'purl', 'supplier', 'license', 'licenseSource', 'tier', 'copyleft', 'inheritedFrom', 'linkage'];
  const rows = r.components.map(c => [
    c.name, c.version, c.purl || '', c.supplier, c.effectiveLicense, c.licenseSource,
    c.tier, c.copyleft,
    c.taintedBy.map(t => t.name).join(' | '),
    c.taintedBy.map(t => t.linkKind).join(' | ')
  ]);
  const csv = [head, ...rows].map(r2 => r2.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  download('\uFEFF' + csv, 'oss-compliance-inventory.csv', 'text/csv');
});

function download(text, name, type) {
  const blob = new Blob([text], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ------------------------------------------------------------ filters --- */
$('#f-sev').addEventListener('change', () => renderFindings(state.result));
$('#f-search').addEventListener('input', () => renderFindings(state.result));
$('#c-tier').addEventListener('change', () => renderComponents(state.result));
$('#c-search').addEventListener('input', () => renderComponents(state.result));
$('#g-search').addEventListener('input', () => renderGraph(state.result));
$('#g-tier').addEventListener('change', () => renderGraph(state.result));
$('#g-link').addEventListener('change', () => renderGraph(state.result));
$('#g-reset').addEventListener('click', () => { renderGraph(state.result); });
