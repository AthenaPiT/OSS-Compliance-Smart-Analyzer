# OSS Compliance Smart Analyzer

SPDX SBOM visualisation + copyleft risk assessment for in-vehicle software.
Zero dependencies, zero build step, runs entirely in the browser (no SBOM data leaves your machine).

```
oss-compliance-analyzer/
  index.html                     dashboard shell
  assets/styles.css
  src/license-db.js              license knowledge base + SPDX expression parser
  src/spdx.js                    SPDX 2.x parser, dependency graph, NTIA quality checks
  src/risk-engine.js             copyleft classification, propagation, findings, scoring
  src/diff.js                    milestone comparison
  src/report.js                  compliance report, NOTICE file, supplier inquiry
  src/graph.js                   force-directed dependency graph (SVG, no libs)
  src/app.js                     UI wiring
  samples/sample-ivisystem.spdx.json        release 4.2.0
  samples/sample-ivisystem-4.1.0.spdx.json  release 4.1.0 (for diff)
  tools/cli.mjs                  headless CLI: analyze / report / notice / inquiry / diff / gate
  tools/mcp-server.mjs           MCP server (stdio) exposing the engine as agent tools
  tools/smoke-test.mjs           headless test of engine + diff + reports
  tools/ui-smoke-test.mjs        jsdom test of the dashboard
  scripts/build-static.mjs       builds dist/ (deploy output, excludes tools/)
  _headers                       Cloudflare Pages headers
  DEPLOY.md                      step-by-step Cloudflare deployment
```

## Run the web app

```bash
cd oss-compliance-analyzer
python -m http.server 8080      # or: npx serve .
# open http://localhost:8080
```
- **Load demo SBOM** - the 4.2.0 IVI sample.
- **Demo milestone diff** - loads 4.1.0 and 4.2.0 and shows the delta.
- **Compare with previous release...** - load your own baseline SBOM.

## Deploy to Cloudflare

Full walkthrough: **[DEPLOY.md](DEPLOY.md)**. Short version:

```bash
npm run build:static        # clean dist/ - excludes tools/ (Node processes)
npx wrangler login
npm run deploy:pages        # -> https://oss-compliance.pages.dev
```

Then in the dashboard: Pages project → **Custom domains** → add your hostname.

The web app is a pure static site — no backend, no external requests (verified: the only
`http` string in the frontend is the SVG XML namespace). `dist/` is 153 KB.

- Works in a subdirectory too (every reference is relative).
- `_headers` sets security headers and `no-cache` on JS/HTML — there is no content hashing,
  so aggressive caching would leave users on stale code after a redeploy.
- For Git integration: build command `npm run build:static`, output directory `dist`.

**Confidentiality.** All parsing happens in the browser; a supplier SBOM you drag in is
never uploaded anywhere. The deployment is therefore safe even on a public URL — but the
tool itself is worth restricting to your organisation. Put Cloudflare Zero Trust **Access**
in front of it (one application policy, e.g. "allow `@yourcompany.com` emails"); it takes a
few minutes and means the URL is not world-reachable.

**What cannot be deployed to Pages:** `tools/cli.mjs` and `tools/mcp-server.mjs` are Node
processes — they need a filesystem and stdio, which Workers do not provide. Run them locally
or in your build agents. If you later want a hosted API, wrap `src/risk-engine.js` in a
Worker with a `fetch` handler (the engine is pure and has no Node dependencies) rather than
reusing the stdio MCP server.

## Run it headlessly (CI / batch)

```bash
node tools/cli.mjs analyze  samples/sample-ivisystem.spdx.json --format json
node tools/cli.mjs analyze  samples/sample-ivisystem.spdx.json --format csv --out inventory.csv
node tools/cli.mjs report   samples/sample-ivisystem.spdx.json --ecu "Cockpit ECU" --milestone C-Sample --out report.md
node tools/cli.mjs notice   samples/sample-ivisystem.spdx.json --out NOTICE
node tools/cli.mjs inquiry  samples/sample-ivisystem.spdx.json --supplier "Tier-1 GmbH" --out inquiry.md
node tools/cli.mjs diff     samples/sample-ivisystem-4.1.0.spdx.json samples/sample-ivisystem.spdx.json

# Release gate - exits 1 on violation, so it can block a pipeline
node tools/cli.mjs gate samples/sample-ivisystem.spdx.json --max-critical 0 --max-high 5 --min-quality 70
```

`gate` fails on: critical/high findings above the thresholds, SBOM quality below the minimum,
and any unresolved license. Wire it into the supplier delivery pipeline so a bad SBOM is
rejected at intake instead of at the milestone review.

## Run it as an MCP server (agent layer)

```json
{
  "mcpServers": {
    "oss-compliance": {
      "command": "node",
      "args": ["<abs path>/oss-compliance-analyzer/tools/mcp-server.mjs"]
    }
  }
}
```

Tools exposed: `analyze_sbom`, `list_findings`, `find_components`, `explain_component`,
`diff_sboms`, `check_license_compatibility`, `evaluate_license_expression`,
`generate_report`, `release_gate`.

## Tests

```bash
npm run smoke        # engine + diff + reports, no dependencies
npm run smoke:ui     # dashboard in jsdom (npm i -D jsdom, or set JSDOM_ENTRY)
```

---

# Building it step by step

The mistake most people make is starting with the graph. The graph is the easy part.
The hard part is **encoding your compliance rules so they are deterministic and auditable**.
Build in this order.

## Phase 0 — Freeze the rules before writing code (1-2 days, no code)

Do this first, in a spreadsheet, *before* you open an AI coding tool. If you skip it, the AI
will invent a risk model and you will not be able to defend the result to an OEM auditor.

1. **License tier table.** For each license family define: tier, copyleft strength, and the
   concrete obligations it triggers. Start from `src/license-db.js` — it already encodes
   strong / network / weak / file-level copyleft plus the linking exceptions that matter in
   embedded (`u-boot-exception-2.0`, `GCC-exception-3.1`, `Classpath-exception-2.0`,
   `Linux-syscall-note`).
2. **Your release gate.** What blocks a milestone sign-off? A defensible default:
   no unresolved license, no strong copyleft in a statically linked proprietary binary,
   no AGPL anywhere in a connected ECU, no known-incompatible license pair in one executable.
3. **The output you must produce.** Usually: per-component obligation checklist, NOTICE file
   content, source-offer list, and a signed exception register for anything waived.

Deliverable: a Markdown/CSV rules file. This becomes the spec you paste into the AI tool.

## Phase 1 — Ingest and normalise (half a day)

Prompt for your AI coding tool:

> Read an SPDX 2.3 JSON file. Build a normalised component model with: SPDXID, name, version,
> supplier, downloadLocation, copyrightText, purl (from externalRefs), checksums,
> licenseConcluded, licenseDeclared, licenseInfoFromFiles. Build a dependency edge list from
> `relationships`, keeping the relationship type, and classifying each edge as
> static / dynamic / unknown / dev / optional. Find the roots from `documentDescribes`, falling
> back to nodes with no incoming edge. Also parse `hasExtractedLicensingInfos`.
> Ignore packages whose SPDXID matches `SPDXRef-(Document|File)-`.
> Also implement the NTIA minimum-elements check and report which elements are missing.

Done here: `src/spdx.js`.

**Non-negotiable supplier requirements** — put these into your supplier quality agreement,
because without them no tool can give you a defensible answer:

| Requirement | Why |
|---|---|
| SPDX 2.3 JSON, `spdxVersion` present | format baseline |
| `licenseConcluded` filled, not `NOASSERTION` | the only field that carries legal conclusion |
| `externalRefs` with `purl` per package | enrichment + CVE lookup |
| `relationships` with `STATIC_LINK` / `DYNAMIC_LINK` | LGPL verdict depends entirely on this |
| `hasExtractedLicensingInfos` for every `LicenseRef-` | otherwise custom licenses are unreadable |
| `filesAnalyzed: true` + `licenseInfoFromFiles` | catches per-file license divergence |
| `creationInfo.creators` + `created` | NTIA minimum elements |
| One SBOM per **executable / distributed unit**, not one per repo | copyleft is assessed per binary |

## Phase 2 — The risk engine (1-2 days)

This is where all the domain value lives. Order matters:

1. **Expression parser.** SPDX expressions are `A AND (B OR C) WITH D`. Write a small
   recursive-descent parser. Rule: `AND` = worst case (all apply), `OR` = you may elect the
   most favourable — but flag the election so it gets documented.
2. **Classification with exceptions.** `GPL-2.0-or-later WITH u-boot-exception-2.0` is *not*
   the same risk as `GPL-2.0-only`. Handle this or you will flood the report with false
   positives and lose credibility with the supplier.
3. **Propagation.** For every copyleft component, walk *up* the dependency graph.
   `static` or undeclared linkage + strong copyleft = the parent is a derivative work.
   Weak copyleft (LGPL) = the parent is not relicensed, but you owe a relinking mechanism.
   Mark every ancestor as tainted so the graph can show it.
4. **Compatibility conflicts.** GPL-2.0-only + Apache-2.0, EPL + GPL, CDDL + GPL cannot be
   combined in one work. Report per distributed unit.
5. **Findings, not scores.** Each finding = rule id + severity + evidence (the dependency
   path) + the obligation + the recommended action. A score alone is useless in an audit;
   an evidence trail is everything.

Done here: `src/risk-engine.js` and `src/license-db.js`.

Prompt:

> Implement a copyleft risk engine over the model from step 1. For each component resolve the
> effective license as licenseConcluded -> licenseDeclared -> licenseInfoFromFiles -> NOASSERTION.
> Classify it into CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN. Then propagate: for each strong
> copyleft component, walk up the dependency graph and mark every ancestor as tainted, using the
> linkage type of the edge (static = derivative work, dynamic = separate work). Emit findings
> with: rule id, severity, title, evidence, the concrete obligation, and a recommended action.
> Dedupe findings per distributed unit, not per hop.

## Phase 3 — Visualise (1 day)

Only now build the UI. Three views are enough; do not build more.

1. **KPI strip** — risk score, critical/high counts, unresolved licenses, SBOM quality %.
2. **Dependency graph** — force-directed, node colour = risk tier, red edge = static link,
   ring around a node = tainted transitively, click = detail panel. This is the view that
   makes the supplier conversation short.
3. **Findings table + component inventory** — filterable, exportable.

Done here: `src/graph.js`, `src/app.js`, `index.html`.

Prompt:

> Build a zero-dependency force-directed graph on SVG. Nodes carry id, label, colour, radius
> (by degree) and a tainted flag. Edges carry a linkage type. Support pan, wheel zoom, node
> drag, hover highlight of the neighbourhood, and click-to-select. Cap rendering at 600 nodes
> by keeping roots, high-risk and high-degree nodes, and report how many were hidden.
> Stop the animation loop once the layout settles.

## Phase 4 — Productise (1-2 weeks)

The browser prototype has no persistence. Add, in this order:

1. **Backend** (Node/TS or Python FastAPI) with the same engine imported — the engine must stay
   pure and headless so the CLI, the API and the UI all share one verdict.
2. **Storage** — one row per (supplier, ECU, milestone, SBOM). Keep every SBOM: the value is in
   the diff between milestones.
3. **SBOM diff** — done here (`src/diff.js`, `cli.mjs diff`, UI diff card). New and removed
   components, version bumps, *license changed* (e.g. OpenSSL `OpenSSL` -> `Apache-2.0`),
   newly introduced copyleft, regressions back to `NOASSERTION`, new vs. closed findings.
   On the demo pair it correctly reports: AGPL MQTT client added, `gpsd` removed,
   OpenSSL relicensed, `legacy-codec` regressed to `NOASSERTION`, 2 new critical findings.
4. **Approval workflow** — per-finding state: open / waived / supplier-answered / accepted,
   with an approver and a reason. Auditors ask for the waiver register, not the scan.
5. **CI gate** — run the engine in the build pipeline, fail the build on new CRITICAL findings.
6. **Report generation** — obligation checklist, NOTICE file, source-offer package list,
   per-ECU compliance report (PDF/DOCX).

## Phase 5 — The agent layer (1 week, and only after Phase 4)

Once the engine is a clean set of pure functions, wrapping it as an agent is mechanical.
Expose the engine as tools and let an LLM orchestrate:

| Tool | What it does |
|---|---|
| `parse_sbom(file)` | parse + NTIA quality report |
| `assess_copyleft(sbom_id)` | findings, score, obligations |
| `explain_finding(id)` | why it fired, with the dependency path |
| `find_components(license=, tier=, supplier=)` | inventory queries |
| `diff_sboms(a, b)` | milestone comparison |
| `check_license_compatibility(list)` | pairwise check |
| `generate_obligation_report(ecu, milestone)` | NOTICE + source-offer list |
| `draft_supplier_inquiry(finding_id)` | write the email to the supplier |

Build it as an MCP server so the same tools work in any MCP-capable client, and keep the
LLM *out* of the verdict path — the LLM should explain and draft, never decide the risk tier.

`tools/mcp-server.mjs` is a working, dependency-free implementation of exactly this
(JSON-RPC 2.0 over stdio). Test it:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_sbom","arguments":{"path":"samples/sample-ivisystem.spdx.json"}}}' \
  | node tools/mcp-server.mjs
```

---

# Extending the license database

Add entries to `LICENSE_RULES` in `src/license-db.js`. Matching is **longest-prefix,
case-insensitive**, so `lgpl-2.` covers `LGPL-2.0-only`, `LGPL-2.1-or-later`, `LGPL-2.1+`.

```js
{ match: 'lgpl-2.', tier: 'HIGH', cat: 'weak-copyleft',
  obl: ['notice', 'state-changes', 'source-modified', 'relinking'],
  note: 'Static linking in monolithic firmware is the most common compliance gap.' }
```

To relax a copyleft license via an exception, add to `LINKING_EXCEPTIONS`.
To add a known incompatibility, add to `COMPAT`.

Enrichment worth adding later (all optional, keep the tool usable offline):
SPDX license list, ClearlyDefined, deps.dev (by purl), OSV / NVD (CVE),
and a `LicenseRef-` text classifier once you have real legal-reviewed samples.

---

# Known limitations — read before you trust a result

- **Not legal advice.** Every CRITICAL/HIGH finding needs legal confirmation.
- **Distributed-unit granularity.** Compatibility conflicts are computed over the transitive
  subtree of a root. Two components in *different processes* do not actually conflict.
  You need an executable/process boundary map to make this precise — request it from the supplier.
- **`DEPENDS_ON` is not a linkage statement.** If the SBOM only uses `DEPENDS_ON`, the tool
  conservatively assumes static linkage. That over-reports; it is the safe direction, but
  expect pushback from suppliers.
- **No per-file analysis.** A package with `filesAnalyzed: false` is taken at its declared
  license. Real audits need file-level scanning (ScanCode / FOSSology) to catch mixed files.
- **License text is not matched**, only license IDs and a keyword heuristic for `LicenseRef-`.
- **Score is a triage aid**, normalised by component count. Do not use it as an SLA metric.
