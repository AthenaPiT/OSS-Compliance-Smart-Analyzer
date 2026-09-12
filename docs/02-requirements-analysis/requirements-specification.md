# Requirements Specification
## OSS Compliance Smart Analyzer (OCSA)

| Field | Value |
|---|---|
| Document ID | SRS-OCSA-001 |
| Version | 1.0 |
| Status | Baseline — Phase 1 |
| Date | 2026-09-12 |
| Owner | Software Quality Management |

---

## 1. Purpose and scope

This document specifies the requirements for OCSA, a tool that ingests an SPDX SBOM delivered
by a supplier, visualises its dependency structure, and assesses copyleft (OSS license
compliance) risk for in-vehicle software.

It covers Phase 1 (delivered prototype). Requirements deferred to Phase 2 are listed in
section 10 and marked for traceability.

### 1.1 Definitions

| Term | Definition |
|---|---|
| **SBOM** | Software Bill of Materials; here an SPDX 2.x JSON document |
| **Component** | A package entry in the SBOM (`packages[]`) |
| **Copyleft** | License condition requiring derivative works to be released under the same or compatible terms |
| **Strong copyleft** | GPL, AGPL, OSL, EUPL, CPAL, RPL, Sleepycat — obligations reach the combined work |
| **Weak copyleft** | LGPL, MPL, EPL, CDDL, MS-RL — obligations are limited to the library or to individual files |
| **Distributed unit** | The artefact actually shipped (an executable, an ECU image). Represented by an SBOM root package |
| **Propagation** | Transmission of a copyleft obligation from a component to its ancestors in the dependency graph |
| **Taint** | Marking applied to a component that transitively depends on copyleft code |
| **Distributed unit root** | SBOM package identified by `documentDescribes`, or a package with no incoming dependency edge |
| **purl** | Package URL, from `externalRefs` — the stable cross-release identity of a component |

---

## 2. Stakeholders and users

| Stakeholder | Interest | Use of the tool |
|---|---|---|
| SQM engineer (primary user) | Sign off OSS compliance per milestone | Runs analysis, reviews findings, generates supplier inquiry |
| Legal counsel | Confirm license obligations | Reviews CRITICAL/HIGH findings; ratifies the tier table |
| Internal review board | Milestone gate decision | Receives the generated compliance report |
| Supplier | Must answer compliance inquiries | Receives the generated inquiry letter |
| OEM auditor | Verify due diligence | Receives compliance report + waiver register (Phase 2) |

### 2.1 User profile — primary user

Works in automotive software quality, fluent in compliance concepts but not a software
developer. Needs a tool that produces a defensible verdict with evidence, not a code library.
Runs on a locked-down Windows workstation; cannot install services or use admin rights.

**Consequence for design:** no installation step, no server, no account. The tool must work by
opening a URL or running a single command.

---

## 3. Business requirements

| ID | Requirement |
|---|---|
| BR-01 | Every supplier-delivered SBOM shall be assessed for copyleft risk before milestone sign-off |
| BR-02 | The assessment shall be reproducible and produce identical results for identical input |
| BR-03 | Every adverse finding shall cite the evidence (dependency path) that produced it |
| BR-04 | The assessment shall be evidence that due diligence was performed, suitable for OEM audit |
| BR-05 | Supplier SBOM content shall not be transmitted to any third party |
| BR-06 | License changes between milestones shall be detected, not merely re-assessed |
| BR-07 | The tool shall be usable by a non-developer without training |

---

## 4. Functional requirements

Priority: **M** = must (Phase 1), **S** = should (Phase 1 if feasible), **C** = could,
**W** = won't (this phase).

### 4.1 Ingestion

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-01 | Parse SPDX 2.2 and 2.3 JSON | M | Document with 42 packages and 45 relationships yields 42 components, 45 edges | TC-13 |
| FR-02 | Extract per package: SPDXID, name, version, supplier, downloadLocation, copyrightText, checksums, purl | M | All fields populated in the component detail panel | TC-17 |
| FR-03 | Build a dependency graph from `relationships` | M | Edges oriented parent→child; `documentDescribes` identifies the root | TC-14 |
| FR-04 | Classify each edge as static / dynamic / unknown / dev / optional linkage | M | `STATIC_LINK` → static, `DYNAMIC_LINK` → dynamic, `DEPENDS_ON` → unknown, `DEV_DEPENDENCY_OF` → dev | TC-03, TC-04 |
| FR-05 | Parse `hasExtractedLicensingInfos` | M | Custom `LicenseRef-` text available for inspection | TC-19 |
| FR-06 | Ignore non-package elements (`SPDXRef-Document-`, `SPDXRef-File-`) | M | No phantom components in inventory | TC-13 |
| FR-07 | Report parse errors with an actionable message | M | Non-SPDX JSON rejected with "No packages array found. Is this an SPDX JSON file?" | TC-30 |
| FR-08 | Accept a file by drag-and-drop or file picker | M | Both paths load the document | TC-09 |
| FR-09 | Load a bundled demo SBOM without a file | S | "Load demo SBOM" renders the sample | TC-08 |

### 4.2 SBOM quality

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-10 | Check the 7 NTIA minimum elements | M | Supplier, name, version, purl, relationships, author, timestamp each reported pass/fail | TC-20 |
| FR-11 | Check 5 additional audit elements (checksums, download location, copyright, filesAnalysed, declared linkage) | M | 12 checks total, presented with counts | TC-20 |
| FR-12 | Present a single SBOM quality percentage | M | `passed / total` rendered as a percentage | TC-12 |

### 4.3 License classification

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-13 | Classify each license into 5 tiers: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN | M | GPL-2.0 → CRITICAL; LGPL-2.1 → HIGH; MIT → LOW; NOASSERTION → UNKNOWN | TC-01 … TC-08 |
| FR-14 | Parse SPDX expressions with `AND`, `OR`, `WITH` and parentheses | M | `(MIT OR Apache-2.0) AND GPL-2.0-only` → CRITICAL | TC-11, TC-12 |
| FR-15 | `AND` evaluates to the worst-case tier | M | `GPL-2.0-or-later AND LGPL-2.1-or-later` → CRITICAL | TC-06 |
| FR-16 | `OR` evaluates to the most favourable tier and flags the election | M | `LGPL-2.1 OR GPL-2.0` → HIGH + LIC-007 finding | TC-05, TC-18 |
| FR-17 | Apply linking exceptions that relax copyleft | M | `GPL-2.0+ WITH u-boot-exception-2.0` → HIGH; `GPL-3.0 WITH GCC-exception-3.1` → HIGH | TC-02, TC-03 |
| FR-18 | Exception with no relaxation effect must not downgrade | M | `GPL-2.0-only WITH Linux-syscall-note` stays CRITICAL | TC-04 |
| FR-19 | Scan custom `LicenseRef-` text for copyleft indicators | M | Text mentioning "GNU General Public License" raises LIC-004 | TC-19 |
| FR-20 | Treat `NOASSERTION` / `NONE` / empty as unresolved | M | Raises LIC-003 | TC-17 |
| FR-21 | Treat a `LicenseRef-` **with** extracted text as resolved for copyleft purposes | S | No LIC-003 for it; tier remains UNKNOWN for review | TC-16 |

### 4.4 Risk analysis

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-22 | Raising LIC-001 for every strong/network copyleft component | M | busybox (GPL-2.0) raises LIC-001 CRITICAL | TC-15 |
| FR-23 | Raising LIC-003 for unresolved licenses | M | legacy-codec raises LIC-003 HIGH | TC-17 |
| FR-24 | Raising LIC-004 for custom licenses with copyleft text | M | vendor-camera-sdk raises LIC-004 CRITICAL | TC-19 |
| FR-25 | Raising LIC-005 for incompatible license pairs in one distributed unit | M | GPL-2.0-only + Apache-2.0 conflict reported | TC-21 |
| FR-26 | Raising LIC-006 when copyleft propagates into a distributed unit | M | AGPL MQTT client propagates into IVI-HMI-Application | TC-16, TC-27 |
| FR-27 | Raising LIC-007 for multi-licensed components | M | ffmpeg (LGPL OR GPL) raises LIC-007 | TC-18 |
| FR-28 | Raising LIC-008 for missing copyright text | M | autosar-bsw raises LIC-008 MEDIUM | TC-22 |
| FR-29 | Raising LIC-009 for LGPL linked without a declared relinking mechanism | M | Qt raises LIC-009 HIGH | TC-15 |
| FR-30 | Mark every ancestor of a copyleft component as tainted | M | telematics-agent tainted by eclipse-mosquitto-client | TC-27 |
| FR-31 | Emit findings **once per distributed unit**, not per intermediate hop | M | No duplicate LIC-006 for the same (source, root) pair | TC-28 |
| FR-32 | Each finding carries rule ID, severity, title, component, evidence, obligation, recommended action | M | All seven fields present in UI and exports | TC-24 |
| FR-33 | Compute a 0–100 risk score normalised by component count | M | Score does not monotonically increase with SBOM size | TC-20 |
| FR-34 | Derive an obligation set per component from its license | M | LGPL yields source-modified + relinking | TC-23 |

### 4.5 Visualisation

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-35 | Render a force-directed dependency graph | M | SVG with nodes and edges; pan, zoom, drag, hover-neighbourhood | TC-31 … TC-34 |
| FR-36 | Colour nodes by risk tier | M | Five distinct colours matching the legend | TC-32 |
| FR-37 | Distinguish linkage by edge style | M | Red = static, blue = dynamic, dashed = dev | TC-33 |
| FR-38 | Ring components tainted by transitive copyleft | M | Red ring on tainted nodes | TC-32 |
| FR-39 | Show KPI strip: score, critical, high, blockers, tainted, quality | M | Six cards render | TC-10 |
| FR-40 | Show license distribution bar chart | M | 14 bars for the demo SBOM | TC-11 |
| FR-41 | Filter the graph by name/license, tier and linkage | M | Filter reduces node and edge counts | TC-35 |
| FR-42 | Open a detail panel on component selection | M | License, obligations, dependencies, dependents, taint sources | TC-36 |
| FR-43 | Filter and search findings and inventory tables | M | Search narrows rows | TC-25, TC-26 |
| FR-44 | Cap graph rendering for very large SBOMs | S | >600 nodes → cap applied, hidden count reported | (manual) |

### 4.6 Milestone comparison

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-45 | Match components across releases by stable identity (purl minus version, else name) | M | A version bump is a change, not add+remove | TC-29 |
| FR-46 | Report added and removed components | M | AGPL MQTT client added; gpsd removed | TC-37, TC-38 |
| FR-47 | Report license changes and flag escalation | M | OpenSSL `OpenSSL`→`Apache-2.0`; legacy-codec MIT→NOASSERTION flagged escalated | TC-39, TC-40 |
| FR-48 | Report version changes | M | Qt 6.5.2 → 6.5.3 | TC-41 |
| FR-49 | Report newly introduced and removed copyleft | M | AGPL MQTT client listed as new copyleft | TC-42 |
| FR-50 | Report regressions back to unresolved | M | legacy-codec listed | TC-43 |
| FR-51 | Report new and closed findings with severity counts | M | 2 new critical findings | TC-44 |
| FR-52 | Report risk-score and quality deltas | M | +3 risk delta | TC-45 |
| FR-53 | Render the diff in the UI and in markdown | M | Diff card + `cli.mjs diff` output | TC-46, TC-47 |

### 4.7 Outputs and interfaces

| ID | Requirement | Pri | Acceptance criteria | Verified by |
|---|---|---|---|---|
| FR-54 | CLI `analyze` with JSON / markdown / CSV output | M | All three formats produced | TC-48 |
| FR-55 | CLI `report` producing a compliance report | M | Verdict, findings, obligation checklist, source-offer list | TC-49, TC-50 |
| FR-56 | CLI `notice` producing a NOTICE attribution file | M | Per-component blocks with license, source, copyright | TC-51 |
| FR-57 | CLI `inquiry` producing a supplier inquiry letter | M | Numbered items with response blanks | TC-52 |
| FR-58 | CLI `gate` exiting non-zero on policy violation | M | Exit 1 with reasons; exit 0 when thresholds allow | TC-53, TC-54 |
| FR-59 | MCP server exposing the engine as tools over stdio | M | 9 tools listable and callable | TC-55 … TC-58 |
| FR-60 | Export findings and inventory as JSON / CSV from the UI | M | Downloads produced | TC-24 |
| FR-61 | Relinking-obligation and source-offer lists in the report | M | Sections present | TC-50 |

---

## 5. Domain rules

### 5.1 License tier model

| Tier | Rank | Categories | Meaning |
|---|---|---|---|
| CRITICAL | 5 | strong-copyleft, network-copyleft | Distribution triggers source disclosure of the derivative work |
| HIGH | *3* | weak-copyleft, file-copyleft | Obligations attach to the library or to modified files |
| UNKNOWN | *3.5* | unknown, custom-ref, unrecognised, proprietary | Release blocker until triaged |
| MEDIUM | 2 | conditional, non-commercial, no-derivatives, share-alike, ambiguous | Requires review |
| LOW | 1 | permissive, public-domain | Notice and attribution only |

> UNKNOWN (3.5) intentionally outranks HIGH (3) so that `GPL-2.0 AND NOASSERTION` resolves to
> CRITICAL rather than masking the copyleft.

### 5.2 Propagation rules

| Condition | Consequence | Finding |
|---|---|---|
| Strong copyleft + static or undeclared linkage into a distributed unit | Combined work is a derivative work | LIC-006 CRITICAL |
| Strong copyleft + dynamic linkage | Separate work; confirm replaceability | LIC-006 HIGH (reported) |
| Weak copyleft (LGPL) + static or undeclared linkage | Relinking mechanism required | LIC-009 HIGH |
| Weak copyleft + dynamic linkage | No finding | — |
| Any copyleft ancestor | Ancestor marked tainted (graph ring) | — |

**Conservative default:** `DEPENDS_ON` carries no linkage information. The tool treats it as
static — over-reporting is the safe direction and is disclosed as a known limitation.

### 5.3 Finding rule catalogue

| Rule | Severity | Trigger |
|---|---|---|
| LIC-001 | CRITICAL | Component is strong or network copyleft |
| LIC-003 | HIGH | License unresolved (NOASSERTION / empty / no extracted text) |
| LIC-004 | CRITICAL / HIGH | Custom `LicenseRef-` text contains copyleft indicators |
| LIC-005 | HIGH / MEDIUM | Incompatible license pair within one distributed unit |
| LIC-006 | CRITICAL | Copyleft propagates into a distributed unit |
| LIC-007 | MEDIUM | Multi-licensed (`OR`) — election must be documented |
| LIC-008 | MEDIUM | Copyright text missing or NOASSERTION |
| LIC-009 | HIGH | LGPL linked without a declared relinking mechanism |

> LIC-002 is **reserved but not implemented** — its intended behaviour (weak copyleft static
> link) is covered by LIC-009.

### 5.4 Release gate criteria

A distributed unit passes when **all** hold:
- Zero CRITICAL findings (unless an approved waiver exists — Phase 2)
- HIGH findings within the configured threshold
- Zero unresolved licenses
- SBOM quality at or above the configured minimum

---

## 6. Non-functional requirements

| ID | Category | Requirement | Verification |
|---|---|---|---|
| NFR-01 | Confidentiality | No SBOM content leaves the user's machine; no external network calls | Static scan: zero external URLs in frontend; verified |
| NFR-02 | Performance | 42-component SBOM analysed and rendered in under 2 s | Observed during TC-08 |
| NFR-03 | Scalability | SBOMs up to ~1 000 nodes render; larger SBOMs down-sampled with a visible indicator | 600-node cap implemented |
| NFR-04 | Determinism | Identical input always produces identical findings and score | Repeat execution in TC-13 |
| NFR-05 | Portability | Runs in any modern browser; CLI and MCP on Node.js 18+ | Verified on Node 22.22.2 |
| NFR-06 | Installability | No build step, no package installation for the web app | `dist/` served statically |
| NFR-07 | Maintainability | Engine is pure functions with no I/O, shared by UI, CLI and MCP | Architecture review |
| NFR-08 | Usability | Primary user achieves a verdict without training | Demo SBOM + one button |
| NFR-09 | Auditability | Every finding traceable to a rule ID and evidence path | FR-32 |
| NFR-10 | Deployability | Single static folder deployable to any CDN | `dist/` 281 KB |
| NFR-11 | Robustness | Malformed input produces a clear message, not a crash | TC-30 |
| NFR-12 | Accessibility | Readable contrast in dark theme; keyboard-operable controls | Manual review |
| NFR-13 | Legal safety | Output labelled engineering triage, never a legal verdict | Banner + report disclaimer |

---

## 7. Data requirements

Input: SPDX 2.2 / 2.3 JSON. Required elements and their use:

| SPDX element | Required | Used for |
|---|---|---|
| `spdxVersion`, `name`, `creationInfo` | Yes | Document identity, NTIA-6/7 |
| `packages[]` | Yes | Component inventory |
| `packages[].licenseConcluded` | Preferred | Primary license source |
| `packages[].licenseDeclared` | Fallback | Secondary license source |
| `packages[].licenseInfoFromFiles` | Fallback | Tertiary source |
| `packages[].externalRefs` (purl) | Strongly preferred | NTIA-4, stable cross-release identity |
| `packages[].checksums` | Preferred | AUD-1 |
| `packages[].copyrightText` | Preferred | AUD-3, LIC-008, NOTICE file |
| `packages[].downloadLocation` | Preferred | AUD-2 |
| `packages[].supplier` | Preferred | NTIA-1, supplier inquiry |
| `relationships[]` | Yes | Dependency graph, NTIA-5 |
| `relationships[].relationshipType` = STATIC_LINK / DYNAMIC_LINK | Strongly preferred | AUD-5, propagation verdict |
| `hasExtractedLicensingInfos[]` | Yes when `LicenseRef-` used | LIC-004, FR-21 |
| `documentDescribes` | Preferred | Root / distributed unit identification |

---

## 8. Interface requirements

| Interface | Consumer | Form |
|---|---|---|
| Web dashboard | SQM engineer | Browser, dark theme, English |
| CLI | CI pipeline, batch | `node tools/cli.mjs <command>` |
| MCP server | AI agent / MCP client | JSON-RPC 2.0 over stdio |
| Exports | Review board, supplier | JSON, CSV, Markdown, NOTICE text |

---

## 9. Supplier SBOM requirements (to be placed in quality agreements)

These are **requirements on our suppliers**, necessary for the tool to produce a defensible
verdict:

| # | Requirement | Rationale |
|---|---|---|
| S-1 | SPDX 2.3 JSON | Format baseline |
| S-2 | `licenseConcluded` populated, not `NOASSERTION` | Only field carrying a legal conclusion |
| S-3 | purl in `externalRefs` for every package | Stable identity; enables enrichment |
| S-4 | `STATIC_LINK` / `DYNAMIC_LINK` relationships | LGPL verdict depends entirely on linkage |
| S-5 | `hasExtractedLicensingInfos` for every `LicenseRef-` | Otherwise custom licenses are unreadable |
| S-6 | `filesAnalyzed: true` with `licenseInfoFromFiles` | Catches per-file divergence |
| S-7 | `creationInfo.creators` and `created` | NTIA minimum elements |
| S-8 | One SBOM per distributed unit (executable / ECU image), not per repository | Copyleft is assessed per shipped artefact |

---

## 10. Requirements deferred to Phase 2

| ID | Requirement | Rationale |
|---|---|---|
| P2-01 | Persistent storage of SBOMs and findings per (supplier, ECU, milestone) | Needed for history and waivers |
| P2-02 | Approval / waiver workflow with approver and reason | Auditors ask for the waiver register |
| P2-03 | CycloneDX ingestion | Some suppliers do not emit SPDX |
| P2-04 | Per-file license scanning integration (ScanCode / FOSSology) | Catches mixed-license files |
| P2-05 | CVE correlation via OSV / NVD using purl | Security use case adjacent to compliance |
| P2-06 | Executable / process boundary map per ECU | Removes conservative over-reporting of conflicts |
| P2-07 | Multi-user accounts and role-based access | Team use |
| P2-08 | PDF / DOCX report export | Distribution to review board |

---

## 11. Traceability matrix

> The "Verified by" cells in section 4 are indicative pointers. The authoritative definition
> and numbering of test cases (TC-01 … TC-58, MV-01 … MV-13) is
> [`docs/05-testing/smoke-test-report.md`](../05-testing/smoke-test-report.md).

| Requirement group | Module | Verification |
|---|---|---|
| FR-01 … FR-09 (ingestion) | `src/spdx.js`, `src/app.js` | TC-13, TC-14, TC-36 … TC-39, MV-13 |
| FR-10 … FR-12 (quality) | `src/spdx.js` (`checkSbomQuality`) | TC-23, TC-43 |
| FR-13 … FR-21 (classification) | `src/license-db.js` | TC-01 … TC-12, TC-16, TC-17 |
| FR-22 … FR-34 (risk analysis) | `src/risk-engine.js` | TC-15 … TC-22, TC-24 |
| FR-35 … FR-44 (visualisation) | `src/graph.js`, `src/app.js` | TC-40 … TC-53 |
| FR-45 … FR-53 (comparison) | `src/diff.js`, `src/report.js` | TC-25 … TC-31, TC-54 … TC-58 |
| FR-54 … FR-61 (interfaces) | `tools/cli.mjs`, `tools/mcp-server.mjs`, `src/report.js` | MV-01 … MV-12 |
| NFR-01 (confidentiality) | all | Static URL scan (zero external URLs) |
| NFR-05, NFR-06, NFR-10 | `scripts/build-static.mjs`, `DEPLOY.md` | MV-13 |
| S-1 … S-8 (supplier requirements) | `DEPLOY.md`, README | Supplier agreement update |

---

*End of document.*
