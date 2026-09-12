# Smoke Test Report
## OSS Compliance Smart Analyzer (OCSA)

| Field | Value |
|---|---|
| Document ID | STR-OCSA-001 |
| Version | 1.0 |
| Status | Final — Phase 1 |
| Date | 2026-09-12 |
| Test lead | SQM Engineering |
| Result | **PASS — 58/58 automated assertions, 13/13 manual verifications** |

> This report is the authoritative definition of test case IDs (TC-01 … TC-58). The
> "Verified by" column in the requirements specification points at these IDs.

---

## 1. Test objectives

1. Verify that the domain engine produces correct, deterministic verdicts on representative
   license expressions and a realistic SBOM.
2. Verify that the web dashboard renders every view without runtime errors.
3. Verify that the CLI and MCP interfaces operate correctly and that the CI gate returns the
   right exit codes.
4. Record every defect found and its resolution.

## 2. Scope

| In scope | Out of scope |
|---|---|
| License expression evaluation | Visual design review |
| SBOM parsing and graph construction | Cross-browser compatibility (Chromium only) |
| Copyleft classification and propagation | Load testing beyond ~1 000 nodes |
| Finding generation (8 rules) | Legal correctness of the tier table |
| SBOM quality checks (12) | Real supplier SBOMs (not yet available) |
| Milestone diff | Accessibility audit |
| Report / NOTICE / inquiry rendering | |
| Dashboard rendering and filtering | |
| CLI commands and exit codes | |
| MCP protocol and tool dispatch | |
| Static build and MIME types | |

## 3. Test environment

| Item | Value |
|---|---|
| OS | Windows (win32) |
| Runtime | Node.js v22.22.2 |
| Browser engine (UI tests) | jsdom 30.0.1 |
| UI test invocation | `JSDOM_ENTRY=… node tools/ui-smoke-test.mjs` |
| Engine test invocation | `node tools/smoke-test.mjs` |
| Test data | `samples/sample-ivisystem.spdx.json` (4.2.0), `samples/sample-ivisystem-4.1.0.spdx.json` |
| Test data profile | 42 components, 45 relationships, 1 root |

## 4. Test strategy

| Level | Approach | Automation |
|---|---|---|
| Unit | License expression evaluation against known-answer cases | Automated (12) |
| Component | Parsing, classification, propagation, findings, scoring on a fixture SBOM | Automated (12) |
| Component | Milestone diff against a 4.1.0 / 4.2.0 pair | Automated (7) |
| Component | Report / NOTICE rendering | Automated (4) |
| Integration | Dashboard rendering in jsdom; filters; detail panel; diff card | Automated (23) |
| System | CLI commands, exit codes, MCP protocol | Manual, scripted (13) |
| Build | `dist/` contents and MIME types over HTTP | Manual, scripted |

**Test data design.** The 4.2.0 fixture deliberately contains the failure modes that matter:
an AGPL component statically linked into a proprietary telematics agent, LGPL components
statically linked without declared relinking, a `NOASSERTION` component, a custom `LicenseRef-`
whose extracted text mentions the GPL, and CDDL/EPL components that conflict with GPL in the
same subtree. The 4.1.0 fixture is derived from it with four controlled differences so that
every diff path has a known expected result.

---

## 5. Test cases and results

### 5.1 A — License expression evaluation (automated)

| ID | Input | Expected | Actual | Result |
|---|---|---|---|---|
| TC-01 | `GPL-2.0-only` | CRITICAL | CRITICAL | PASS |
| TC-02 | `GPL-2.0-or-later WITH u-boot-exception-2.0` | HIGH | HIGH | PASS |
| TC-03 | `GPL-3.0-only WITH GCC-exception-3.1` | HIGH | HIGH | PASS |
| TC-04 | `GPL-2.0-only WITH Linux-syscall-note` | CRITICAL | CRITICAL | PASS |
| TC-05 | `LGPL-2.1-or-later OR GPL-2.0-or-later` | HIGH | HIGH | PASS |
| TC-06 | `GPL-2.0-or-later AND LGPL-2.1-or-later` | CRITICAL | CRITICAL | PASS |
| TC-07 | `MIT` | LOW | LOW | PASS |
| TC-08 | `Apache-2.0` | LOW | LOW | PASS |
| TC-09 | `AGPL-3.0-only` | CRITICAL | CRITICAL | PASS |
| TC-10 | `NOASSERTION` | UNKNOWN | UNKNOWN | PASS |
| TC-11 | `LicenseRef-Foo` | UNKNOWN | UNKNOWN | PASS |
| TC-12 | `(MIT OR Apache-2.0) AND GPL-2.0-only` | CRITICAL | CRITICAL | PASS |

> TC-02/03 verify that linking exceptions relax copyleft; TC-04 verifies that an exception
> with no relaxation effect (`Linux-syscall-note`) does **not** downgrade the verdict.

### 5.2 B — SBOM model and risk analysis (automated)

| ID | Objective | Expected | Actual | Result |
|---|---|---|---|---|
| TC-13 | All packages parsed | 42 components | 42 | PASS |
| TC-14 | Root identified | `SPDXRef-Pkg-IVI-HMI-Application` | as expected | PASS |
| TC-15 | LGPL statically linked raises LIC-009 | Finding present | present (Qt) | PASS |
| TC-16 | Unresolved license raises LIC-003 | Finding present | present (legacy-codec) | PASS |
| TC-17 | Custom license text raises LIC-004 | Finding present | present (vendor-camera-sdk) | PASS |
| TC-18 | Multi-licensing raises LIC-007 | Finding present | present (ffmpeg) | PASS |
| TC-19 | Incompatibility raises LIC-005 | Finding present | present | PASS |
| TC-20 | Propagation raises LIC-006 | Finding present | present (6 sources) | PASS |
| TC-21 | AGPL classified CRITICAL | `eclipse-mosquitto-client` = CRITICAL | CRITICAL | PASS |
| TC-22 | Taint reaches the parent | `telematics-agent` tainted by AGPL client | tainted | PASS |
| TC-23 | Quality checks present | 12 checks | 12 | PASS |
| TC-24 | Risk score in range | 0 < score ≤ 100 | 61 | PASS |

**Observed output for the fixture:** score 61 (band HIGH), SBOM quality 50 % (6/12),
findings CRITICAL 13 / HIGH 30 / MEDIUM 8 = 51 total.

### 5.3 C — Milestone diff 4.1.0 → 4.2.0 (automated)

| ID | Objective | Expected | Actual | Result |
|---|---|---|---|---|
| TC-25 | Added component detected | `eclipse-mosquitto-client` | detected | PASS |
| TC-26 | Removed component detected | `gpsd` | detected | PASS |
| TC-27 | License change detected | `OpenSSL` → `Apache-2.0` | detected | PASS |
| TC-28 | Escalation flagged | `legacy-codec` MIT → NOASSERTION | flagged escalated | PASS |
| TC-29 | Regression to unresolved detected | `legacy-codec` | detected | PASS |
| TC-30 | Version bump detected | Qt 6.5.2 → 6.5.3 | detected | PASS |
| TC-31 | New critical findings counted | > 0 | 2 | PASS |

### 5.4 D — Report generation (automated)

| ID | Objective | Expected | Actual | Result |
|---|---|---|---|---|
| TC-32 | Compliance report contains verdict | `Risk score nn/100` | present | PASS |
| TC-33 | Report contains obligation checklist | section present | present | PASS |
| TC-34 | Report contains source-offer section | section present | present | PASS |
| TC-35 | NOTICE file contains attributions | `NOTICES AND ATTRIBUTIONS` | present | PASS |

### 5.5 E — Dashboard in jsdom (automated)

| ID | Objective | Expected | Actual | Result |
|---|---|---|---|---|
| TC-36 | No runtime errors | 0 errors | 0 | PASS |
| TC-37 | Dashboard becomes visible | `#dashboard` shown | shown | PASS |
| TC-38 | Landing zone hidden | `#dropzone` hidden | hidden | PASS |
| TC-39 | Header shows document identity | contains document name | `IVI-Cockpit-SW-4.2.0 … 42 components` | PASS |
| TC-40 | KPI strip renders | 6 cards | 6 | PASS |
| TC-41 | Risk score displayed | numeric | 61 | PASS |
| TC-42 | License distribution renders | > 5 bars | 14 | PASS |
| TC-43 | Quality table renders | 12 rows | 12 | PASS |
| TC-44 | Findings render | > 10 rows | 51 | PASS |
| TC-45 | Critical badge rendered | ≥ 1 | 1+ | PASS |
| TC-46 | Inventory renders | 42 rows | 42 | PASS |
| TC-47 | Graph SVG created | element exists | exists | PASS |
| TC-48 | Graph nodes drawn | > 20 circles | 85 | PASS |
| TC-49 | Graph edges drawn | > 20 lines | 45 | PASS |
| TC-50 | Graph statistics label | `nn nodes / nn edges` | `42 nodes / 45 edges` | PASS |
| TC-51 | Tier filter narrows inventory | 0 < rows < 42 | 6 | PASS |
| TC-52 | Detail panel opens | class `open` | opens | PASS |
| TC-53 | Detail shows license | `Effective license` | present | PASS |
| TC-54 | Diff card renders | `Milestone diff` | present | PASS |
| TC-55 | Diff shows new component | `eclipse-mosquitto-client` | present | PASS |
| TC-56 | Diff shows removed component | `gpsd` | present | PASS |
| TC-57 | Diff shows license change | `OpenSSL` | present | PASS |
| TC-58 | Diff verdict severity | CRITICAL | CRITICAL | PASS |

### 5.6 F — CLI and MCP (manual, scripted)

| ID | Command / action | Expected | Actual | Result |
|---|---|---|---|---|
| MV-01 | `cli.mjs analyze … --format json` | Valid JSON with score, findings, components | Produced | PASS |
| MV-02 | `cli.mjs analyze … --format csv` | 43 lines (header + 42) | 43 | PASS |
| MV-03 | `cli.mjs analyze … --format md` | Markdown report | Produced | PASS |
| MV-04 | `cli.mjs report … --ecu … --milestone …` | Report with metadata table | Produced | PASS |
| MV-05 | `cli.mjs notice …` | NOTICE with per-component blocks | Produced | PASS |
| MV-06 | `cli.mjs inquiry … --supplier …` | Numbered items with response blanks | Produced | PASS |
| MV-07 | `cli.mjs diff <old> <new>` | Markdown diff with all sections | Produced | PASS |
| MV-08 | `cli.mjs gate <file>` (strict) | Exit 1 + reasons | Exit 1, 3 reasons | PASS |
| MV-09 | `cli.mjs gate … --max-critical 99 --max-high 99 --allow-unresolved` | Exit 0 | Exit 0 | PASS |
| MV-10 | MCP `initialize` | protocolVersion + capabilities + serverInfo | Returned | PASS |
| MV-11 | MCP `tools/list` | 9 tools with JSON Schemas | 9 | PASS |
| MV-12 | MCP `tools/call` × 4 (expression, compatibility, analyze, release_gate) | Correct payloads | Correct | PASS |
| MV-13 | `build:static` + HTTP serve | `dist/` 281 KB; 200 + correct MIME for html/css/js/png/json | Verified | PASS |

---

## 6. Execution summary

| Suite | Cases | Passed | Failed | Pass rate |
|---|---|---|---|---|
| A — License expressions | 12 | 12 | 0 | 100 % |
| B — Model and analysis | 12 | 12 | 0 | 100 % |
| C — Milestone diff | 7 | 7 | 0 | 100 % |
| D — Report generation | 4 | 4 | 0 | 100 % |
| E — Dashboard (jsdom) | 23 | 23 | 0 | 100 % |
| **Automated total** | **58** | **58** | **0** | **100 %** |
| F — CLI / MCP / build (manual) | 13 | 13 | 0 | 100 % |
| **Grand total** | **71** | **71** | **0** | **100 %** |

Exit codes: engine suite `0`, UI suite `0`.

---

## 7. Bug register

All defects were found during development and verification. All are **closed**.

| ID | Severity | Component | Description | Root cause | Resolution |
|---|---|---|---|---|---|
| BUG-01 | High | `license-db.js` | UNKNOWN licenses reported as HIGH | HIGH and UNKNOWN both had rank 4, so `find(t => t.rank === r)` matched HIGH first | UNKNOWN re-ranked to 3.5; ranks are now unique |
| BUG-02 | High | `license-db.js` | `GPL-2.0+ WITH u-boot-exception-2.0` classified UNKNOWN instead of HIGH | Relaxation ladder contained UNKNOWN, so CRITICAL relaxed onto it | Ladder restricted to `[LOW, MEDIUM, HIGH, CRITICAL]` |
| BUG-03 | **Critical** | `license-db.js` | Second and later lookups of a license returned no rank → NaN → UNKNOWN verdict | Classification cache stored the object *before* `rank` was computed | Rank computed before caching |
| BUG-04 | High | `license-db.js` | LIC-003 never fired for `NOASSERTION` | Early-return object omitted `unresolved: true` | Field added |
| BUG-05 | Medium | `risk-engine.js` | 30+ spurious HIGH findings — LIC-003 fired for every `LicenseRef-` | Proprietary refs with extracted text treated as unknown-unknowns | A ref with extracted text is resolved for copyleft purposes (tier stays UNKNOWN) |
| BUG-06 | Medium | `risk-engine.js` | 22 identical "copyleft propagates into …" findings for one AGPL component | Findings emitted per intermediate hop | Emitted only when the target is a distributed-unit root; ancestors still tainted |
| BUG-07 | Medium | `cli.mjs` | `--allow-unresolved` had no effect; gate could never pass | Boolean flag read with the value-flag helper, which consumes the next argv | Dedicated `has()` helper; positional parsing corrected |
| BUG-08 | Medium | `risk-engine.js` | Risk score saturated at 100 on every realistic SBOM | Raw weighted finding count × 4 | Density-normalised formula (see architecture §5.3) |
| BUG-09 | High | `index.html` / `app.js` | `renderDiff` crashed: "Cannot set properties of null" | `#diff-card` container missing from the markup | Container added |
| BUG-10 | Low | `ui-smoke-test.mjs` | Diff assertions failed — diff was empty | The `fetch` stub returned the same document for both URLs | Stub made URL-aware |
| BUG-11 | Low | `spdx.js` | `licenseDeclared` extraction incorrect | Operator-precedence bug in a ternary | Simplified to `p.licenseDeclared \|\| ''` |
| BUG-12 | Low | `graph.js` | Animation loop never terminated, burning CPU | No settle condition | Motion threshold stops the loop; interaction wakes it |
| BUG-13 | Medium | `risk-engine.js` | Ancestor paths could be malformed or miss entries | Fragile index arithmetic in path construction | Rewritten as a cycle-safe BFS returning `{node, linkKind, hops}` |
| BUG-14 | Low | `graph.js` | Syntax error `raf = null;.alpha = 0;` | Typo during editing | Corrected; caught by `node --check` |
| BUG-15 | Low | `spdx.js` | purl extraction used an incorrect `reduce` | Over-engineered parsing | Simplified to a `referenceType` check |
| BUG-16 | Low | `app.js` | Header showed only the filename, not the SBOM document name | Missing field in the header string | Header now shows `name — filename — SPDX version — N components` |
| BUG-17 | Low | `risk-engine.js` | All LIC-006 findings had identical titles | Title omitted the source component | Title now names the source |

### 7.1 Defect distribution

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 4 |
| Medium | 5 |
| Low | 7 |
| **Total** | **17** |

| Component | Count |
|---|---|
| `license-db.js` | 4 |
| `risk-engine.js` | 4 |
| `spdx.js` | 2 |
| `graph.js` | 2 |
| `cli.mjs` | 1 |
| `app.js` / `index.html` | 2 |
| `ui-smoke-test.mjs` | 1 |
| `tools` (other) | 1 |

> BUG-03 is the notable one: it was silent and order-dependent — a license evaluated correctly
> on first use and incorrectly once cached. It was only caught because the test suite evaluates
> `GPL-2.0-only` twice with different modifiers. Known-answer repetition is what surfaced it.

---

## 8. Coverage analysis

| Area | Covered by | Status |
|---|---|---|
| Expression grammar (AND/OR/WITH/parens) | TC-01 … TC-12 | Covered |
| Linking exceptions (relaxing and non-relaxing) | TC-02, TC-03, TC-04 | Covered |
| Classification of unknown / custom references | TC-10, TC-11, TC-17 | Covered |
| All 8 finding rules | TC-15 … TC-20, TC-22 (+ LIC-001 observed in output) | Covered except LIC-008 by assertion (observed in output only) |
| Propagation and taint | TC-20, TC-22 | Covered |
| Scoring | TC-24 | Covered (range check only — no golden value) |
| Quality checks | TC-23 | Covered (count only) |
| Diff — all categories | TC-25 … TC-31 | Covered |
| Report / NOTICE | TC-32 … TC-35 | Covered |
| UI rendering and filtering | TC-36 … TC-58 | Covered |
| CLI and MCP | MV-01 … MV-12 | Covered (manual) |
| Build and MIME types | MV-13 | Covered (manual) |

### 8.1 Coverage gaps (honest assessment)

| Gap | Risk | Recommendation |
|---|---|---|
| LIC-008 (missing copyright) is not asserted | Low | Add an assertion in the next cycle |
| Scoring has no golden-value test | Medium | Pin expected scores for both fixtures so a formula change is caught |
| LIC-001 not asserted directly | Low | Assert explicitly |
| Graph is tested structurally, not visually | Medium | One manual visual check per release |
| No negative tests for malformed SPDX beyond the missing-`packages` case | Medium | Add fixtures: cyclic relationships, missing `relationships`, empty document |
| No cross-browser testing | Medium | Manual check in Firefox/Edge before wide rollout |
| CLI/MCP are manual | Medium | Automate MV-01 … MV-12 |

---

## 9. Residual risk

| ID | Risk | Severity | Mitigation |
|---|---|---|---|
| RR-01 | Tier table not legally ratified — all verdicts are engineering triage | **High** | M-8; legal workshop |
| RR-02 | No real supplier SBOM tested; fixtures are synthetic | Medium | First live run must be compared against manual review |
| RR-03 | Compatibility conflicts may over-report without a process-boundary map | Medium | Documented; request boundary maps |
| RR-04 | Single browser engine tested | Medium | Manual cross-browser check |
| RR-05 | No persistence, so historical re-analysis requires the original files | Low | Phase 2 (P2-01) |

---

## 10. Conclusion and recommendations

The Phase 1 prototype **passes all 58 automated assertions and all 13 manual verifications**,
with 17 defects found and closed. The build is reproducible (`dist/` 281 KB) and serves
correctly over HTTP.

**Recommendations before operational use:**

1. **Do not treat the green suite as validation of correctness.** It validates that the
   implementation matches the current rules. The rules themselves need legal ratification
   (M-8). Until then every CRITICAL/HIGH finding requires counsel.
2. **Automate the manual cases.** MV-01 … MV-12 are scripted but not asserted; promoting them
   prevents regression in the CLI and MCP surfaces.
3. **Add golden-value tests for the score** so a formula change is visible.
4. **Add negative fixtures** — cyclic relationships, missing `relationships`, empty document.
5. **Run against one real supplier SBOM** and compare with the manual review to calibrate the
   false-positive rate before rollout.

---

## 11. Appendix A — reproduction

```bash
cd oss-compliance-analyzer

# Automated engine suite (35 assertions, no dependencies)
node tools/smoke-test.mjs

# Automated UI suite (23 assertions, needs jsdom)
npm i -D jsdom
node tools/ui-smoke-test.mjs

# Manual CLI / MCP checks
node tools/cli.mjs gate samples/sample-ivisystem.spdx.json
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | node tools/mcp-server.mjs

# Build verification
npm run build:static && (cd dist && python -m http.server 8080)
```

## 12. Appendix B — engine suite output (excerpt)

```
PASS  evaluate("GPL-2.0-only") => CRITICAL - got CRITICAL
PASS  evaluate("GPL-2.0-or-later WITH u-boot-exception-2.0") => HIGH - got HIGH
PASS  evaluate("GPL-2.0-only WITH Linux-syscall-note") => CRITICAL - got CRITICAL
PASS  evaluate("(MIT OR Apache-2.0) AND GPL-2.0-only") => CRITICAL - got CRITICAL

Document: IVI-Cockpit-SW-4.2.0 (SPDX SPDX-2.3)
Components: 42, relationships: 45, roots: SPDXRef-Pkg-IVI-HMI-Application
Risk score: 61 (HIGH)  SBOM quality: 50%
Findings: CRITICAL=13 HIGH=30 MEDIUM=8

Top findings:
  [CRITICAL] LIC-006 Strong copyleft from "busybox" propagates into "IVI-HMI-Application"
  [CRITICAL] LIC-006 Strong copyleft from "linux-kernel" propagates into "IVI-HMI-Application"
  [CRITICAL] LIC-006 Strong copyleft from "eclipse-mosquitto-client" propagates into "IVI-HMI-Application"
  [CRITICAL] LIC-004 Custom license text on vendor-camera-sdk shows copyleft indicators
  [CRITICAL] LIC-001 Strong copyleft component: busybox

Diff 4.1.0 -> 4.2.0: 2 new critical finding(s) (risk +3)

ALL CHECKS PASSED
```

---

*End of report.*
