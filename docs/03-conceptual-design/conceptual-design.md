# Conceptual Design
## OSS Compliance Smart Analyzer (OCSA)

| Field | Value |
|---|---|
| Document ID | CDD-OCSA-001 |
| Version | 1.0 |
| Status | Baseline |
| Date | 2026-09-12 |

---

## 1. Product concept

**One sentence:** Drop a supplier's SPDX SBOM into a browser, and get back a visual dependency
map plus a prioritised, evidence-backed list of OSS license obligations — without the SBOM ever
leaving your machine.

The product is deliberately a **decision-support instrument for a human reviewer**, not an
automated compliance authority. Every output is framed as triage that a qualified engineer —
and ultimately legal counsel — confirms. This framing is a design decision, not a hedge: it
keeps the tool useful while preventing it from being misused as a legal verdict.

### 1.1 The three questions it answers

1. **What is in this software?** — component inventory, versions, suppliers, purls.
2. **What does it oblige us to do?** — obligation checklist, source-offer list, relinking list.
3. **What changed since the last milestone?** — added/removed components, license changes,
   newly introduced copyleft, regressions.

### 1.2 What it deliberately does not do

- Does not decide whether something is legally acceptable.
- Does not require a server, account, or network access.
- Does not attempt to scan source code.
- Does not manage the approval workflow (Phase 2).

---

## 2. Functional map

```
OCSA
│
├── Ingest
│   ├── SPDX 2.x JSON parsing
│   ├── Package / relationship / extracted-license normalisation
│   └── NTIA minimum-elements + audit quality check
│
├── Assess
│   ├── License expression evaluation (AND / OR / WITH)
│   ├── Copyleft classification (5 tiers, 12 categories)
│   ├── Linking-exception handling
│   ├── Transitive propagation (static vs dynamic)
│   ├── License compatibility conflicts
│   ├── Obligation derivation
│   └── Normalised risk scoring
│
├── Visualise
│   ├── Dependency graph (force-directed, risk-coloured)
│   ├── KPI strip
│   ├── License distribution
│   └── Findings + inventory tables
│
├── Compare
│   ├── Identity-based component matching
│   ├── Change / escalation / regression detection
│   └── Markdown + UI diff rendering
│
├── Report
│   ├── Compliance report (markdown)
│   ├── NOTICE attribution file
│   ├── Supplier inquiry letter
│   ├── JSON / CSV export
│   └── CI release gate
│
└── Expose (agent layer)
    └── MCP server — 9 tools over stdio
```

---

## 3. Core domain concepts

| Concept | Definition | Why it matters |
|---|---|---|
| **Component** | A package in the SBOM with a resolved *effective license* | The unit of assessment |
| **Effective license** | `licenseConcluded` → `licenseDeclared` → `licenseInfoFromFiles` → NOASSERTION | Suppliers populate these inconsistently; the fallback chain is what makes real SBOMs usable |
| **Distributed unit** | The shipped artefact; SBOM root | Copyleft attaches to the *shipped work*, not to a repository |
| **Linkage** | static / dynamic / unknown / dev / optional | The single biggest determinant of a copyleft outcome |
| **Taint** | Ancestor-of-copyleft marker | Shows *reachability*, which is what makes a risk real or theoretical |
| **Obligation** | A concrete action (disclose source, provide relinking, include notice) | The actual deliverable of compliance work |
| **Finding** | Rule + severity + evidence + obligation + action | The audit artefact |
| **Identity** | purl minus version, else lowercased name | Without it, a version bump looks like a removal plus an addition |

### 3.1 The mental model the UI enforces

```
                ┌──────────────┐
                │ Distributed  │  ← what you ship
                │    unit      │
                └──────┬───────┘
                       │ depends on
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   ┌────────┐    ┌──────────┐   ┌──────────┐
   │ LGPL   │    │  GPL     │   │   MIT    │
   │ (weak) │    │ (strong) │   │(permissive)
   └────────┘    └──────────┘   └──────────┘
   relinking     derivative      notice only
   required      work —          (no copyleft)
                 disclose source
```

The graph view exists to make this picture instantly legible: red nodes are strong copyleft,
red edges are static links, and a red ring means "this is reachable from copyleft".

---

## 4. Design rationale

Every significant decision, with the alternative that was rejected.

### DR-1 — Rules before code

**Decision:** Freeze the license tier table, obligations and gate criteria in a table before
writing any code.
**Rationale:** The domain model is the product. If an AI coding tool invents the risk model,
the result cannot be defended to an OEM auditor. The tier table is the artefact legal will
actually ratify.
**Rejected:** Starting from the graph UI and inferring rules later — produces a pretty tool
with an undefensible verdict.

### DR-2 — Browser-first, server-free

**Decision:** All parsing and analysis run client-side in JavaScript.
**Rationale:** Supplier SBOMs are confidential; NFR-01 forbids third-party transmission. A
server would require hosting, accounts, and a data-processing justification. A browser app
sidesteps all of it and needs no installation.
**Rejected:** Backend service — unnecessary infrastructure, and it would make reviewers
reluctant to paste in real supplier data.

### DR-3 — Zero runtime dependencies

**Decision:** No framework, no charting library, no graph library. The force layout is
implemented in ~60 lines.
**Rationale:** The tool must work on a locked-down corporate workstation with no npm access,
must survive years without dependency rot, and must be deployable as a static folder. It also
keeps the supply chain of the compliance tool itself trivial — an irony worth avoiding.
**Rejected:** React + D3 + Cytoscape — three dependencies to review in a tool whose purpose is
dependency review.

### DR-4 — Findings, not scores

**Decision:** The primary output is a list of findings, each with rule ID, severity, evidence
path, obligation and recommended action. A 0–100 score exists but is secondary.
**Rationale:** A score is meaningless in an audit; an evidence trail is everything. Reviewers
act on findings, and suppliers respond to findings.
**Rejected:** Score-only dashboard — impossible to action or defend.

### DR-5 — Density-normalised scoring

**Decision:** Score combines *density* (share of components that are critical/high/unknown/
tainted) with blocker density and a quality penalty — not a raw finding count.
**Rationale:** Raw counts grow with SBOM size, so a large clean project would score worse than
a small dirty one. Density keeps the score comparable across ECUs and milestones.
**Rejected:** Weighted sum of finding counts — measured to saturate at 100 on the first
realistic SBOM, destroying all signal.

### DR-6 — Conservative linkage default

**Decision:** When the SBOM only declares `DEPENDS_ON`, treat linkage as static.
**Rationale:** In automotive firmware, linking is overwhelmingly static. Assuming dynamic
would systematically under-report the most common real-world violation.
**Rejected:** Assuming dynamic — under-reports; assuming "unknown and skip" — silently drops
the majority of real SBOMs.
**Mitigation:** Every such finding states "linkage not declared", so the supplier can correct it.

### DR-7 — Model linking exceptions explicitly

**Decision:** Handle `WITH <exception>` and maintain a relaxation table
(`u-boot-exception-2.0`, `GCC-exception-3.1`, `Classpath-exception-2.0`, …).
**Rationale:** `GPL-2.0-or-later WITH u-boot-exception-2.0` is materially different from
`GPL-2.0-only`. Ignoring exceptions floods the report with false positives and destroys
credibility with suppliers — the fastest way to get a tool ignored.
**Rejected:** Treating all GPL as equally critical.

### DR-8 — `OR` = most favourable, but flag the election

**Decision:** `A OR B` evaluates to the lower-risk tier, and raises LIC-007 instructing the
reviewer to document which license was elected.
**Rationale:** Dual licensing genuinely grants a choice — scoring the worst case would be
wrong. But the choice must be recorded, because it determines the obligation actually owed.
**Rejected:** Worst-case for `OR` (over-reports); silent best-case (loses the audit trail).

### DR-9 — Deduplicate findings per distributed unit

**Decision:** Propagation findings are emitted once per (copyleft source, root) pair, not once
per intermediate hop.
**Rationale:** First implementation produced 22 identical "copyleft propagates into …" entries
for one AGPL component with several ancestors — unusable. Intermediate ancestors are still
marked tainted, so no information is lost.
**Rejected:** Per-hop findings — measured, and rejected on usability grounds.

### DR-10 — `LicenseRef-` with extracted text is "resolved for copyleft purposes"

**Decision:** A custom license reference whose text is supplied in
`hasExtractedLicensingInfos` does not raise the unresolved blocker (LIC-003); it stays UNKNOWN
tier for review.
**Rationale:** It is not an unknown-unknown. Raising a blocker for every proprietary
`LicenseRef-` produced 30+ HIGH findings and buried the real ones.
**Rejected:** Treating all `LicenseRef-` as blockers — measured to be unusable.

### DR-11 — Engine stays pure; interfaces are thin

**Decision:** `src/risk-engine.js`, `src/license-db.js`, `src/spdx.js` and `src/diff.js`
contain no I/O. The browser, the CLI and the MCP server are thin adapters over the same
functions.
**Rationale:** One verdict, three surfaces. If the engine had I/O, the CLI and UI could drift
apart and produce different answers to the same question.
**Rejected:** Separate implementations per surface.

### DR-12 — The LLM explains, never decides

**Decision:** In the MCP/agent layer, every verdict comes from the deterministic engine. The
model may summarise, explain and draft correspondence.
**Rationale:** A non-deterministic component in the verdict path makes the result unauditable.
**Rejected:** Letting the model assign risk tiers.

### DR-13 — Deploy a clean `dist/`, not the repository

**Decision:** A build script copies only browser-facing files to `dist/`, excluding `tools/`.
**Rationale:** `tools/` contains Node processes with filesystem and stdio access. Publishing
them to a corporate URL is unnecessary exposure.
**Rejected:** Deploying the repository root.

---

## 5. Technologies and tools

| Layer | Choice | Rationale | Alternatives rejected |
|---|---|---|---|
| Language | JavaScript (ES 2022 modules) | Runs in browser and Node unchanged; no compile step | TypeScript (adds build step); Python (cannot run in browser) |
| Runtime | Node.js ≥ 18 (CLI, MCP, tests) | Already available; ES module support | Deno, Bun (not standard on corporate machines) |
| UI framework | **None** — vanilla DOM | No install, no build, no dependency review | React, Vue (build step, supply chain) |
| Graph rendering | Hand-written force layout on SVG | ~60 lines; full control; zero deps | D3-force, Cytoscape, vis-network |
| Charts | Hand-written SVG bars | Trivial need | Chart.js |
| Styling | Plain CSS with custom properties | Themeable, no preprocessor | Tailwind (build step) |
| Module system | Native ES modules | No bundler; works with `file://` forbidden but any static server fine | Webpack, Vite |
| Test (engine) | Node's built-in `assert`-style script | Zero dependencies | Jest, Mocha (npm install) |
| Test (UI) | jsdom | Runs the real DOM in Node; dev-only | Playwright (browser download, heavy) |
| Sample data | Hand-authored SPDX 2.3 JSON | Representative of real IVI/cockpit BOMs | Synthetic generator (less realistic) |
| Deployment | Cloudflare Pages (static) | Already used by the organisation; free tier; custom domain | Netlify, GitHub Pages, internal server |
| Agent interface | MCP over stdio, hand-written JSON-RPC | No SDK dependency; works with any MCP client | `@modelcontextprotocol/sdk` (extra dependency) |
| Docs | Markdown | Version-controllable, readable anywhere | Confluence (not local) |

### 5.1 Tooling summary

| Tool | Version | Purpose |
|---|---|---|
| Node.js | 22.22.2 | CLI, MCP server, tests, build script |
| jsdom | 30.0.1 | UI smoke test (dev-only, optional) |
| Python `http.server` | 3.x | Local preview (any static server works) |
| Wrangler | latest | Cloudflare Pages deployment |
| Git | — | Version control, Pages Git integration |

---

## 6. Preliminary architecture

### 6.1 Layered view

```
┌──────────────────────────────────────────────────────────────┐
│  Presentation                                                 │
│  index.html · assets/styles.css · src/app.js · src/graph.js   │
│  Dashboard, graph, tables, detail panel, export               │
└──────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────┐
│  Interfaces (thin adapters)                                   │
│  tools/cli.mjs        analyze · report · notice ·             │
│                       inquiry · diff · gate                   │
│  tools/mcp-server.mjs 9 tools over JSON-RPC/stdio             │
└──────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────┐
│  Domain engine (pure, no I/O)                                 │
│  src/spdx.js        parse · graph · NTIA quality              │
│  src/license-db.js  tiers · obligations · expression parser   │
│  src/risk-engine.js classification · propagation · findings    │
│  src/diff.js        milestone comparison                      │
│  src/report.js      report · NOTICE · inquiry                 │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 Data flow — a single analysis

```
SPDX JSON
   │  parseSpdx()
   ▼
normalised { packages, relationships, extractedLicenses, roots }
   │  checkSbomQuality()                    ──►  quality report
   │  buildDependencyGraph()
   ▼
{ edges, children, parents }
   │  analyze()
   │    ├─ pickLicense()        effective license per component
   │    ├─ evaluateExpression() tier + obligations
   │    ├─ collectAncestors()   propagation → taint
   │    ├─ checkCompatibility() conflicts
   │    └─ computeScore()       normalised 0-100
   ▼
{ components, findings, score, licenseStats, obligations }
   │
   ├─► renderGraph()     force-directed SVG
   ├─► renderFindings()  prioritised table
   ├─► renderComponents() inventory
   └─► renderComplianceReport() / renderNoticeFile() / renderSupplierInquiry()
```

### 6.3 Data flow — milestone comparison

```
baseline SPDX ──► analyze() ──┐
                              ├─► diffSboms() ──► { added, removed, licenseChanged,
current  SPDX ──► analyze() ──┘                     versionChanged, newCopyleft,
                                                    regressed, newFindings,
                                                    fixedFindings, riskDelta }
                                        │
                                        ├─► renderDiffReport()  (markdown)
                                        └─► renderDiff()        (UI card)
```

### 6.4 Deployment view

```
workstation                     CI / build agent              Cloudflare
───────────                     ────────────────              ──────────
browser ←── dist/  ────────────  npm run build:static  ───►   Pages
 (drag SBOM,                     npm run smoke                  │
  all parsing                    npm run smoke:ui               ├─ custom domain
  local)                         cli.mjs gate ──► exit 1        └─ Zero Trust Access
                                 (blocks pipeline)
```

---

## 7. User interface concept

| Region | Content | Purpose |
|---|---|---|
| Header | Logo, product name, document identity, export and compare actions | Orientation |
| Landing | Drag-and-drop zone, demo buttons | Zero-friction entry |
| Diff card | Baseline → current delta with verdict badge | "What changed?" |
| KPI strip | Score, critical, high, blockers, tainted, quality | 10-second status |
| License distribution | Horizontal bars coloured by tier | Composition |
| SBOM quality | 12 NTIA/audit checks | "Can I trust this SBOM?" |
| Dependency graph | Force-directed, risk-coloured, clickable | Reachability |
| Findings | Severity, rule, evidence, obligation, action | What to do |
| Inventory | Searchable component table | Lookup |
| Detail panel | Full component context incl. taint sources | Drill-down |

**Colour language (dark theme):** red = critical, orange = high, yellow = medium, green = low,
grey = unknown. Red edge = static link, blue = dynamic, dashed = build/dev. Ring = tainted.

---

## 8. Conceptual limitations

Accepted, documented, and surfaced to the user:

1. **Not legal advice.** Legal must confirm CRITICAL/HIGH.
2. **Distributed-unit granularity.** Compatibility conflicts are computed over a root's
   transitive subtree; components in separate processes do not actually conflict. A
   process-boundary map (Phase 2, P2-06) would fix this.
3. **`DEPENDS_ON` is not a linkage statement.** Conservative default (DR-6) over-reports by
   design.
4. **No per-file analysis.** Packages with `filesAnalyzed: false` are taken at their declared
   license.
5. **License text is not parsed**, only IDs plus a keyword heuristic for `LicenseRef-`.
6. **The score is a triage aid**, not an SLA metric.

---

*End of document.*
