# Project Management Plan
## OSS Compliance Smart Analyzer (OCSA)

| Field | Value |
|---|---|
| Document ID | PMP-OCSA-001 |
| Version | 1.0 |
| Status | Approved — Phase 1 (prototype) complete |
| Date | 2026-09-12 |
| Owner | Software Quality Management, OEM supplier |
| Classification | Internal |

---

## 1. Project overview

### 1.1 Background

As a Tier-1 supplier to automotive OEMs, we receive a Software Bill of Materials (SBOM) for
every software release from our own suppliers and from internal development. Our obligation is
to verify that open source software (OSS) is used in accordance with the OEM's software quality
requirements — in particular that copyleft licenses do not create undisclosed obligations on
the delivered product.

The SBOMs arrive as **SPDX JSON**. Reviewing them manually does not scale: a typical cockpit
or IVI release contains 40–200 components with multi-level transitive dependencies, dual
licensing, and custom `LicenseRef-` entries. Manual review also produces inconsistent verdicts
between reviewers, which is indefensible in an OEM audit.

### 1.2 Problem statement

1. No tooling to visualise SBOM dependency structure, so copyleft reachability is invisible.
2. Copyleft assessment is inconsistent and depends on individual reviewer experience.
3. No objective record linking a finding to the evidence (dependency path) that produced it.
4. No milestone-to-milestone comparison, so license changes between releases go unnoticed.
5. Reviews are manual and cannot gate a CI pipeline or a supplier delivery.

### 1.3 Objectives

| ID | Objective | Measure |
|---|---|---|
| OBJ-1 | Automate ingestion and normalisation of SPDX 2.x JSON SBOMs | Parse 100% of supplier SPDX 2.2/2.3 files without manual pre-processing |
| OBJ-2 | Produce deterministic, reproducible copyleft verdicts | Same SBOM always yields identical findings |
| OBJ-3 | Visualise component dependencies and license risk | Reviewer identifies the risk path in under 2 minutes |
| OBJ-4 | Present findings with evidence and a concrete obligation | Every finding carries rule ID + dependency path + action |
| OBJ-5 | Enable milestone comparison | Detect added/removed components and license changes |
| OBJ-6 | Enable automated release gating | Non-zero exit code blocks a pipeline on policy violation |
| OBJ-7 | Keep supplier data confidential | No SBOM content leaves the reviewer's machine |

### 1.4 Success criteria

- [x] Demo SBOM (42 components) analysed end-to-end with 51 findings.
- [x] 58 automated assertions pass (35 engine + 23 UI).
- [x] Milestone diff verified against a 4.1.0 → 4.2.0 pair.
- [x] Deployable as a static site (281 KB `dist/`) to a private corporate domain.
- [ ] (Phase 2) Used on a real supplier delivery in a live milestone review.
- [ ] (Phase 2) Legal sign-off on the license tier table.

---

## 2. Scope

### 2.1 In scope — Phase 1 (delivered)

| Area | Delivered |
|---|---|
| Ingestion | SPDX 2.2 / 2.3 JSON parsing, package/relationship/extracted-license model |
| Quality | NTIA minimum elements + 5 additional audit checks (12 total) |
| Classification | 5-tier license risk model, SPDX expression parser (AND/OR/WITH), linking exceptions |
| Analysis | Copyleft propagation, license compatibility, obligation derivation |
| Reporting | Findings list, risk score, obligation checklist, NOTICE file, supplier inquiry letter |
| Comparison | Milestone diff (identity-based) |
| Visualisation | Dependency graph, KPI strip, license distribution, inventory tables |
| Interfaces | Browser UI, CLI (6 commands), MCP server (9 tools) |
| Deployment | Static site build + Cloudflare Pages guide |

### 2.2 Out of scope — Phase 1

- Legal validation of the license tier table (requires counsel).
- Per-file license scanning (ScanCode / FOSSology integration).
- Vulnerability (CVE) correlation via OSV/NVD.
- CycloneDX format support.
- Persistent storage, user accounts, approval/waiver workflow.
- Hosted multi-tenant backend.
- Commercial license inventory management.

### 2.3 Assumptions

| ID | Assumption | Risk if false |
|---|---|---|
| ASM-1 | Suppliers can deliver SPDX 2.2+ JSON | Parser must handle CycloneDX or conversion |
| ASM-2 | `licenseConcluded` is populated by the supplier | Verdicts fall back to declared/from-files; confidence drops |
| ASM-3 | Reviewers have Node.js 18+ available for CLI/testing | Browser-only usage still works; CLI/MCP unavailable |
| ASM-4 | Legal can review and ratify the tier table within Phase 2 | Tool remains engineering triage only |
| ASM-5 | A process/executable boundary map can be obtained per ECU | Compatibility conflicts stay conservative (over-reported) |

### 2.4 Constraints

| ID | Constraint |
|---|---|
| CON-1 | Supplier SBOMs are confidential — no third-party upload or external API calls |
| CON-2 | No budget for commercial SCA tooling in the current cycle |
| CON-3 | Must run on the reviewer's Windows workstation without admin rights |
| CON-4 | Tool output is engineering triage; it does not replace legal counsel |
| CON-5 | No server-side infrastructure available in Phase 1 |

---

## 3. Deliverables

| ID | Deliverable | Location | Status |
|---|---|---|---|
| D-01 | Working prototype (web application) | `index.html`, `src/`, `assets/` | Complete |
| D-02 | Headless CLI | `tools/cli.mjs` | Complete |
| D-03 | MCP server (agent interface) | `tools/mcp-server.mjs` | Complete |
| D-04 | Automated test suite | `tools/smoke-test.mjs`, `tools/ui-smoke-test.mjs` | Complete |
| D-05 | Sample SBOM fixtures (2 milestones) | `samples/` | Complete |
| D-06 | Deployment package + guide | `scripts/`, `_headers`, `DEPLOY.md` | Complete |
| D-07 | Requirements analysis | `docs/02-requirements-analysis/` | Complete |
| D-08 | Conceptual design | `docs/03-conceptual-design/` | Complete |
| D-09 | Architecture design | `docs/04-architecture-design/` | Complete |
| D-10 | Smoke test report | `docs/05-testing/` | Complete |
| D-11 | Legal ratification of license tier table | — | **Not started** |
| D-12 | Waiver/approval workflow | — | Phase 2 |

---

## 4. Work breakdown structure

```
1  OSS Compliance Smart Analyzer
1.1  Foundation
1.1.1  License knowledge base (tiers, obligations, exceptions)      [done]
1.1.2  SPDX expression parser (AND / OR / WITH)                     [done]
1.1.3  SPDX 2.x document parser + dependency graph                  [done]
1.1.4  NTIA minimum-elements quality checks                         [done]
1.2  Risk engine
1.2.1  Effective license resolution                                 [done]
1.2.2  Copyleft classification                                      [done]
1.2.3  Transitive propagation (static vs dynamic)                   [done]
1.2.4  License compatibility conflicts                              [done]
1.2.5  Finding generation (LIC-001 … LIC-009)                       [done]
1.2.6  Normalised risk scoring                                      [done]
1.3  Presentation
1.3.1  Force-directed dependency graph                              [done]
1.3.2  Dashboard (KPIs, distribution, quality)                      [done]
1.3.3  Findings and inventory tables with filtering                 [done]
1.3.4  Component detail panel                                       [done]
1.3.5  Export (JSON / CSV)                                          [done]
1.4  Interfaces
1.4.1  CLI: analyze / report / notice / inquiry / diff / gate       [done]
1.4.2  MCP server over stdio                                        [done]
1.5  Milestone comparison
1.5.1  Identity-based component matching                            [done]
1.5.2  Change, escalation and regression detection                  [done]
1.5.3  Diff rendering (markdown + UI card)                          [done]
1.6  Verification
1.6.1  Engine smoke test (35 assertions)                            [done]
1.6.2  UI smoke test (23 assertions)                                [done]
1.7  Deployment
1.7.1  Static build script                                          [done]
1.7.2  Cloudflare Pages headers and guide                           [done]
1.8  Documentation
1.8.1  Requirements / conceptual / architecture / test report       [done]
2  Phase 2 (planned)
2.1  Legal ratification of the tier table                           [planned]
2.2  Backend persistence + approval workflow                        [planned]
2.3  CycloneDX support                                              [planned]
2.4  Per-file scanning integration                                  [planned]
2.5  CVE correlation via OSV                                        [planned]
```

---

## 5. Phasing and schedule

Phase 1 was executed as a single intensive iteration. Durations below are elapsed working
time, not calendar time.

| Phase | Work package | Est. | Actual | Status |
|---|---|---|---|---|
| P0 | Rules definition (tier table, obligations, gate criteria) | 1–2 d | ~0.5 d | Complete |
| P1 | Ingestion and normalisation | 0.5 d | ~0.3 d | Complete |
| P2 | Risk engine (classification, propagation, findings, scoring) | 1–2 d | ~0.7 d | Complete |
| P3 | Visualisation (graph, dashboard, tables) | 1 d | ~0.5 d | Complete |
| P4 | Productisation (CLI, diff, reports, CI gate) | 1–2 wk | ~0.4 d | Complete |
| P5 | Agent layer (MCP server) | 1 wk | ~0.2 d | Complete |
| P6 | Verification and defect correction | 0.5 d | ~0.4 d | Complete |
| P7 | Deployment package | 0.5 d | ~0.2 d | Complete |
| P8 | Design documentation | 1 d | ~0.3 d | Complete |
| **Total Phase 1** | | **~4–5 wk** | **~3.5 d (AI-assisted)** | **Complete** |

> The prototype was built with AI-assisted coding. The estimate column reflects conventional
> manual effort; the actual column is not directly comparable and should not be used as a
> baseline for future manual work.

### Milestones

| ID | Milestone | Criteria | Date | Status |
|---|---|---|---|---|
| M-1 | Prototype runs on demo SBOM | Dashboard renders, 42 components | 2026-09-12 | Met |
| M-2 | Engine verified headlessly | 35 assertions pass | 2026-09-12 | Met |
| M-3 | CLI + CI gate operational | `gate` exits 1 on violation | 2026-09-12 | Met |
| M-4 | Milestone diff verified | 4.1.0 → 4.2.0 delta correct | 2026-09-12 | Met |
| M-5 | MCP server responds | 9 tools callable over stdio | 2026-09-12 | Met |
| M-6 | Deployment package ready | `dist/` 281 KB, `_headers` | 2026-09-12 | Met |
| M-7 | Design documentation archived | 5 documents | 2026-09-12 | Met |
| M-8 | Legal ratification of tier table | Counsel sign-off | — | **Open** |
| M-9 | First live supplier review | Real SBOM assessed | — | **Open** |

---

## 6. Roles and responsibilities

| Role | Responsibility | Phase 1 |
|---|---|---|
| SQM Engineer (project owner) | Domain rules, gate criteria, supplier requirements, acceptance | Owner |
| AI coding assistant | Implementation, test authoring, documentation drafting | Executor |
| Legal counsel | Ratify license tier table, review CRITICAL/HIGH findings | **To engage (Phase 2)** |
| Supplier quality manager | Embed SBOM requirements in supplier agreements | **To engage (Phase 2)** |
| IT / Cloudflare admin | Custom domain, DNS, Zero Trust Access policy | **To engage at deployment** |

> Phase 1 had no dedicated developer, tester or DevOps resource. For Phase 2 (persistence,
> workflow, hosted backend) these roles must be staffed.

---

## 7. Risk register

| ID | Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|---|
| R-01 | License tier table is legally wrong | Medium | **Critical** | Tool is labelled engineering triage; legal ratification is M-8; all CRITICAL/HIGH findings require counsel | SQM + Legal |
| R-02 | Suppliers deliver incomplete SBOMs (no linkage, no purl) | **High** | High | NTIA quality check surfaces gaps; conservative "assume static link" default; supplier requirements list published | SQM |
| R-03 | False positives erode trust with suppliers | Medium | High | Linking exceptions modelled explicitly; findings include evidence path; deduplication per distributed unit | SQM |
| R-04 | Compatibility conflicts over-reported (no process boundary map) | **High** | Medium | Documented as a known limitation; request boundary map; isolate per-executable SBOMs | SQM |
| R-05 | Tool used as a legal verdict rather than triage | Medium | **Critical** | Banner in UI, disclaimer in every generated report, README limitations section | SQM |
| R-06 | Large SBOMs (5 000+) degrade graph performance | Low | Medium | 600-node render cap with hidden-count indicator; O(n²) layout acceptable to ~1 000 nodes | Dev |
| R-07 | `LicenseRef-` custom licenses hide copyleft | Medium | High | Extracted-text keyword scan (LIC-004); unresolved-reference blocker (LIC-003) | SQM |
| R-08 | Cloudflare deployment exposes internal tool publicly | Low | Medium | Zero Trust Access policy; also protect `*.pages.dev` URL | IT |
| R-09 | Scope creep into CVE/vulnerability management | Medium | Medium | Explicitly out of scope for Phase 1; planned as Phase 2.5 | SQM |
| R-10 | Single-maintainer knowledge concentration | Medium | Medium | Design documentation (this set) + 58 automated assertions | SQM |

---

## 8. Quality management

### 8.1 Definition of done (per work package)

- [ ] Functional requirement implemented and traceable to an FR ID
- [ ] Automated assertion added and passing
- [ ] No new defect introduced (full suite green)
- [ ] Documented in architecture or README where behaviour is non-obvious
- [ ] Deployable via `npm run build:static` without manual steps

### 8.2 Quality gates

| Gate | Criterion | Status |
|---|---|---|
| G-1 (code) | `npm run smoke` exits 0 | Passed — 35/35 |
| G-2 (UI) | `npm run smoke:ui` exits 0 | Passed — 23/23 |
| G-3 (build) | `dist/` builds and serves all assets with correct MIME types | Passed |
| G-4 (docs) | All five design documents archived | Passed |
| G-5 (legal) | Tier table ratified by counsel | **Not passed — blocks Phase 2 release** |

### 8.3 Verification approach

Two automated suites (engine + UI) run on every change; see
[`docs/05-testing/smoke-test-report.md`](../05-testing/smoke-test-report.md). Defects are
tracked in the bug register within that report.

---

## 9. Configuration and change management

| Item | Detail |
|---|---|
| Source location | `oss-compliance-analyzer/` (workspace) |
| Version scheme | Semantic versioning; current `0.1.0` |
| Build | `npm run build:static` → `dist/` |
| Excluded from deploy | `tools/`, `scripts/`, `package.json`, `docs/`, `dist/` (see `.gitignore`) |
| Change to license tier table | **Controlled change** — affects every verdict; requires re-baselining all historical findings and legal re-review |
| Change to finding rule IDs | Append new IDs; never renumber existing ones (findings are referenced in reports) |

---

## 10. Communication and reporting

| Artefact | Audience | Frequency |
|---|---|---|
| Design documentation set (this) | Project owner, future maintainers, auditors | Once, updated per release |
| Smoke test report | Project owner | Per release |
| Compliance report (generated) | Internal review board, OEM on request | Per milestone |
| Supplier inquiry letter (generated) | Supplier | Per milestone, on blockers |
| Waiver register | Auditor | Per milestone (**Phase 2**) |

---

## 11. Current status and next steps

**Phase 1 is complete and verified.** The prototype is functional, tested, documented and
deployable.

Recommended next actions, in priority order:

1. **Engage legal to ratify the license tier table (M-8).** This is the only gate standing
   between the tool and operational use. It is a table review, not a code task — likely a
   single workshop.
2. **Publish the supplier SBOM requirements** (listed in the README) into supplier quality
   agreements. Without `STATIC_LINK`/`DYNAMIC_LINK` and purls, no tool can produce a
   defensible verdict.
3. **Run the tool against one real supplier SBOM** and compare against the current manual
   review. This calibrates false-positive rate before wider rollout.
4. **Add the waiver/approval workflow (Phase 2).** Auditors ask for the waiver register, not
   the scan.
5. **Deploy to the corporate domain** behind Zero Trust Access using `DEPLOY.md`.

---

*End of document.*
