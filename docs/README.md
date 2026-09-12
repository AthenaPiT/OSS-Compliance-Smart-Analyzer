# Design Documentation — OSS Compliance Smart Analyzer

Archived by work deliverable. Each folder is self-contained.

| # | Folder | Deliverable | Document |
|---|---|---|---|
| 01 | [project-management](01-project-management/) | Project management plan | `project-management-plan.md` |
| 02 | [requirements-analysis](02-requirements-analysis/) | Requirements specification | `requirements-specification.md` |
| 03 | [conceptual-design](03-conceptual-design/) | Conceptual design | `conceptual-design.md` |
| 04 | [architecture-design](04-architecture-design/) | Architecture design | `architecture-design.md` |
| 05 | [testing](05-testing/) | Smoke test report | `smoke-test-report.md` |

## Reading order

1. **01 — Project management plan.** Why the project exists, scope, phases, risks, what is
   done and what is still open. Start here for status.
2. **02 — Requirements specification.** 61 functional requirements (FR-01 … FR-61),
   13 non-functional requirements, the domain rule catalogue, and the supplier SBOM
   requirements to place in quality agreements.
3. **03 — Conceptual design.** Product concept, functional map, core domain concepts,
   13 design-rationale decisions with rejected alternatives, technology choices, and the
   preliminary architecture.
4. **04 — Architecture design.** System context, container and component views, data
   structures, algorithms, deployment topology, 14 architecture decision records, technical
   debt.
5. **05 — Smoke test report.** 58 automated assertions and 13 manual verifications, all
   passing; a 17-entry bug register with root causes; coverage gaps and residual risk.

## Key figures

| Metric | Value |
|---|---|
| Source code | 1 982 LOC in `src/`, 710 LOC in `tools/` + `scripts/`, 301 LOC markup/CSS |
| Runtime dependencies | 0 |
| Automated assertions | 58 (35 engine + 23 UI) — 100 % pass |
| Manual verifications | 13 — 100 % pass |
| Defects found / closed | 17 / 17 |
| Demo SBOM | 42 components, 45 relationships, score 61/HIGH, quality 50 %, 51 findings |
| Deployment payload | `dist/` 281 KB, static |

## The one thing that is still open

The license tier table has **not** been ratified by legal counsel. Until it is, every output
is engineering triage. This is milestone M-8 in the project management plan and the single
gate between the current prototype and operational use.
