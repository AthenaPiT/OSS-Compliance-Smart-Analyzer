/**
 * graph.js - Zero-dependency force-directed dependency graph on SVG.
 * Supports pan, zoom, node drag, hover highlight and selection.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';
const MAX_RENDER_NODES = 600;

export function createGraph(container, { nodes, edges, onSelect, onHover }) {
  container.innerHTML = '';
  const width = container.clientWidth || 900;
  const height = container.clientHeight || 560;

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', '100%');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.style.display = 'block';
  svg.style.cursor = 'grab';
  container.appendChild(svg);

  const defs = document.createElementNS(SVG_NS, 'defs');
  defs.innerHTML = `
    <marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M1 1L9 5L1 9" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
    </marker>`;
  svg.appendChild(defs);

  const root = document.createElementNS(SVG_NS, 'g');
  svg.appendChild(root);
  const edgeLayer = document.createElementNS(SVG_NS, 'g');
  const nodeLayer = document.createElementNS(SVG_NS, 'g');
  root.appendChild(edgeLayer);
  root.appendChild(nodeLayer);

  // Down-sample if the SBOM is huge: keep roots, high-risk and high-degree nodes.
  let renderNodes = nodes, renderEdges = edges, truncated = 0;
  if (nodes.length > MAX_RENDER_NODES) {
    const score = n => (n.rank || 0) * 10 + (n.degree || 0) + (n.isRoot ? 50 : 0) + (n.taintedSeverity ? 30 : 0);
    renderNodes = [...nodes].sort((a, b) => score(b) - score(a)).slice(0, MAX_RENDER_NODES);
    const keep = new Set(renderNodes.map(n => n.id));
    renderEdges = edges.filter(e => keep.has(e.source) && keep.has(e.target));
    truncated = nodes.length - renderNodes.length;
  }

  const sim = renderNodes.map(n => ({
    id: n.id, data: n,
    x: width / 2 + (Math.random() - 0.5) * width * 0.6,
    y: height / 2 + (Math.random() - 0.5) * height * 0.6,
    vx: 0, vy: 0,
    r: n.isRoot ? 15 : 6 + Math.min(7, Math.sqrt((n.degree || 1)) * 2)
  }));
  const simById = new Map(sim.map(s => [s.id, s]));
  const simEdges = renderEdges
    .map(e => ({ s: simById.get(e.source), t: simById.get(e.target), link: e.linkage, dev: e.dev }))
    .filter(e => e.s && e.t && e.s !== e.t);

  let alpha = 1;
  let raf = null;
  let dragging = null;

  function tick() {
    const n = sim.length;
    const repulsion = 900 + n * 6;
    const centerPull = 0.012;

    for (let i = 0; i < n; i++) {
      const a = sim[i];
      for (let j = i + 1; j < n; j++) {
        const b = sim[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) { d2 = 1; dx = Math.random() - 0.5; dy = Math.random() - 0.5; }
        const d = Math.sqrt(d2);
        const f = repulsion / d2;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    for (const e of simEdges) {
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      const rest = 70;
      const f = (d - rest) * 0.012;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      e.s.vx += fx; e.s.vy += fy; e.t.vx -= fx; e.t.vy -= fy;
    }
    for (const a of sim) {
      a.vx += (width / 2 - a.x) * centerPull;
      a.vy += (height / 2 - a.y) * centerPull;
      if (a === dragging) { a.vx = 0; a.vy = 0; continue; }
      a.vx *= 0.82; a.vy *= 0.82;
      a.x += Math.max(-30, Math.min(30, a.vx * alpha));
      a.y += Math.max(-30, Math.min(30, a.vy * alpha));
    }
    let motion = 0;
    for (const a of sim) motion += Math.abs(a.vx) + Math.abs(a.vy);
    alpha = Math.max(0.08, alpha * 0.985);
    draw();
    if (motion / Math.max(1, sim.length) < 0.06 && !dragging && alpha <= 0.081) {
      raf = null;                       // settled - stop burning CPU
      return;
    }
    raf = requestAnimationFrame(tick);
  }

  /* ------------------------------------------------------------ drawing --- */
  const edgeEls = simEdges.map(e => {
    const p = document.createElementNS(SVG_NS, 'line');
    p.setAttribute('stroke', e.dev ? '#3a4256' : e.link === 'static' ? '#ff6b6b' : e.link === 'dynamic' ? '#4dabf7' : '#4b5568');
    p.setAttribute('stroke-width', e.link === 'static' ? 1.6 : 1);
    p.setAttribute('stroke-opacity', e.dev ? 0.25 : 0.5);
    p.setAttribute('marker-end', 'url(#arr)');
    p.setAttribute('color', e.link === 'static' ? '#ff6b6b' : '#4b5568');
    if (e.dev) p.setAttribute('stroke-dasharray', '3 4');
    edgeLayer.appendChild(p);
    return { el: p, e };
  });

  const nodeEls = sim.map(s => {
    const g = document.createElementNS(SVG_NS, 'g');
    g.style.cursor = 'pointer';

    const ring = document.createElementNS(SVG_NS, 'circle');
    ring.setAttribute('r', s.r + 4);
    ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', s.data.taintedSeverity === 'CRITICAL' ? '#ff4d4f' : 'transparent');
    ring.setAttribute('stroke-width', 2);
    g.appendChild(ring);

    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('r', s.r);
    c.setAttribute('fill', s.data.color || '#5b6478');
    c.setAttribute('stroke', '#0e1117');
    c.setAttribute('stroke-width', 1.5);
    g.appendChild(c);

    if (s.data.isRoot) {
      const c2 = document.createElementNS(SVG_NS, 'circle');
      c2.setAttribute('r', s.r + 3);
      c2.setAttribute('fill', 'none');
      c2.setAttribute('stroke', '#e6edf3');
      c2.setAttribute('stroke-width', 1);
      c2.setAttribute('stroke-dasharray', '2 3');
      g.appendChild(c2);
    }

    const label = document.createElementNS(SVG_NS, 'text');
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('y', s.r + 12);
    label.setAttribute('font-size', s.data.isRoot ? 12 : 10);
    label.setAttribute('fill', '#aab6c8');
    label.setAttribute('pointer-events', 'none');
    label.textContent = truncate(s.data.label || s.id, s.data.isRoot ? 28 : 18);
    g.appendChild(label);

    g.addEventListener('mouseenter', () => { highlight(s.id); onHover?.(s.data); });
    g.addEventListener('mouseleave', () => { highlight(null); onHover?.(null); });
    g.addEventListener('mousedown', ev => { ev.stopPropagation(); dragging = s; svg.style.cursor = 'grabbing'; wake(); });
    g.addEventListener('click', ev => { ev.stopPropagation(); onSelect?.(s.data); });

    nodeLayer.appendChild(g);
    return { g, s, ring, circle: c, label };
  });

  function draw() {
    for (const { el, e } of edgeEls) {
      el.setAttribute('x1', e.s.x); el.setAttribute('y1', e.s.y);
      el.setAttribute('x2', e.t.x); el.setAttribute('y2', e.t.y);
    }
    for (const { g, s } of nodeEls) {
      g.setAttribute('transform', `translate(${s.x.toFixed(1)},${s.y.toFixed(1)})`);
    }
  }

  function highlight(id) {
    for (const { g, s } of nodeEls) {
      const on = !id || s.id === id ||
        simEdges.some(e => (e.s.id === id && e.t.id === s.id) || (e.t.id === id && e.s.id === s.id));
      g.setAttribute('opacity', on ? 1 : 0.18);
    }
    for (const { el, e } of edgeEls) {
      const on = !id || e.s.id === id || e.t.id === id;
      el.setAttribute('stroke-opacity', on ? (e.dev ? 0.45 : 0.95) : 0.06);
    }
  }

  function wake() {
    if (raf == null) { alpha = Math.max(alpha, 0.5); raf = requestAnimationFrame(tick); }
    else alpha = Math.max(alpha, 0.5);
  }

  /* --------------------------------------------------------- pan / zoom --- */
  let scale = 1, tx = 0, ty = 0;
  function applyTransform() {
    root.setAttribute('transform', `translate(${tx},${ty}) scale(${scale})`);
  }
  svg.addEventListener('wheel', ev => {
    ev.preventDefault();
    const k = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    const pt = svg.createSVGPoint();
    pt.x = ev.clientX; pt.y = ev.clientY;
    const loc = pt.matrixTransform(svg.getScreenCTM().inverse());
    tx = loc.x - (loc.x - tx) * k;
    ty = loc.y - (loc.y - ty) * k;
    scale = Math.max(0.15, Math.min(6, scale * k));
    applyTransform();
  }, { passive: false });

  svg.addEventListener('mousedown', ev => {
    const start = { x: ev.clientX - tx, y: ev.clientY - ty };
    const move = e => { tx = e.clientX - start.x; ty = e.clientY - start.y; applyTransform(); };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      svg.style.cursor = 'grab';
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  });
  window.addEventListener('mouseup', () => { dragging = null; svg.style.cursor = 'grab'; });

  tick();

  return {
    truncated,
    reset() { scale = 1; tx = 0; ty = 0; applyTransform(); },
    focus(id) {
      const s = simById.get(id);
      if (!s) return;
      scale = 1.6;
      tx = width / 2 - s.x * scale;
      ty = height / 2 - s.y * scale;
      applyTransform();
      highlight(id);
    },
    stop() { if (raf) cancelAnimationFrame(raf); raf = null; alpha = 0; },
    resume() { wake(); }
  };
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
