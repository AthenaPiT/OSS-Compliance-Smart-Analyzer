# Deploying to your own domain on Cloudflare

Time: about 15 minutes. You need a Cloudflare account and the ability to add a DNS record.
Nothing in this project needs a server — it is a static site.

Before you start, decide the hostname, e.g. `oss.example.com`. You cannot use a path on
someone else's site; it must be a hostname you control.

---

## Step 0 — Build the clean output folder

```bash
cd oss-compliance-analyzer
npm run build:static
```

This creates `dist/` with **only** `index.html`, `_headers`, `assets/`, `src/`, `samples/`
(153 KB). It deliberately excludes `tools/` (the CLI and MCP server — Node processes with
filesystem access) and `package.json`, so they never reach a public URL.

Checkpoint: `ls dist` should show five entries and no `tools`.

---

## Step 1 — Get the files onto Cloudflare

Pick one route.

### Route A — Wrangler from your machine (fastest, no Git needed)

```bash
npx wrangler login          # opens a browser, authorises the CLI
npm run deploy:pages
```

First run asks you to confirm the project name and prints the preview URL:
`https://oss-compliance.pages.dev`.

### Route B — Git integration (re-deploys on every push)

1. Push the project to GitHub or GitLab.
2. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
3. Select the repository, then set:

   | Setting | Value |
   |---|---|
   | Framework preset | None |
   | Build command | `npm run build:static` |
   | Build output directory | `dist` |

4. Save and deploy.

> Cloudflare has been merging Pages into Workers. If your dashboard only offers **Workers**,
> use `npx wrangler deploy` with static assets instead, or create the Pages project via
> Wrangler (Route A) — both end in the same place.

Checkpoint: open the `*.pages.dev` URL. Click **Demo milestone diff**. If the diff card
appears, the upload is good. If the page is blank, see Troubleshooting.

---

## Step 2 — Add your custom domain

1. Open the Pages project → **Custom domains** → **Set up a custom domain**.
2. Enter your hostname (`oss.example.com`) → **Continue**.

Then it depends on where your DNS lives.

### Case 1 — the domain already uses Cloudflare DNS

Cloudflare adds the DNS record itself. Nothing to do.
Wait for the certificate: the status goes `Initializing` → `Active`, usually under five
minutes, occasionally up to an hour.

### Case 2 — DNS is with another provider (or another team owns the apex)

Pages needs the zone in your Cloudflare account. Two options:

- **Move the whole domain to Cloudflare DNS** — Cloudflare walks you through the nameserver
  change. Cleanest, but it affects everything on the domain, so get the DNS owner's sign-off.
- **Delegate only the subdomain** — add these records at your current provider:
  ```
  oss.example.com.   NS   <name1>.ns.cloudflare.com.
  oss.example.com.   NS   <name2>.ns.cloudflare.com.
  ```
  then add `oss.example.com` as a zone in Cloudflare (they tell you which two nameservers to
  use). This touches nothing else — a good option in a company where apex DNS is locked down.

> Using the bare apex (`example.com` with no subdomain) works **only** if the domain is on
> Cloudflare DNS, because Cloudflare flattens the CNAME at the root. With external DNS, use a
> subdomain.

Checkpoint: `https://oss.example.com` loads the app and the padlock is valid.

---

## Step 3 — Lock it down (recommended)

No SBOM is ever uploaded — parsing happens in the browser — so a public URL leaks no data.
But this is internal tooling; keep it off the open internet.

1. Cloudflare dashboard → **Zero Trust** → **Access** → **Applications** → **Add an application** → **Self-hosted**.
2. Application domain: `oss.example.com` (all paths).
3. Add a policy: **Allow** → **Emails ending in** → `@yourcompany.com`. Save.

Now do the same for `oss-compliance.pages.dev`, or the login bypasses your policy by using
the default URL. Alternatively add a **Bulk Redirect** from `oss-compliance.pages.dev` to
your custom domain.

Also worth setting, on the zone: **SSL/TLS → Overview → Full (strict)**.

---

## Step 4 — Verify

```bash
curl -I https://oss.example.com
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://oss.example.com/src/app.js
```

Expect `200` and `text/javascript`. If `src/app.js` returns `text/plain` or `text/html`,
ES modules will be blocked and the page renders blank.

Then in the browser: load **Demo milestone diff** and confirm the diff card appears.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Blank page, console shows a module MIME error | `src/*.js` not served as `text/javascript`. Confirm the deploy included `src/` and that no rule rewrites content types. |
| 525 / 526 on the custom domain | Certificate still issuing. Wait; check status on the Custom domains tab. |
| Works on `pages.dev`, fails on custom domain | DNS record missing or not proxied — should be a CNAME to `<project>.pages.dev`, orange cloud on. |
| Old version after a redeploy | Browser cached `src/`. `_headers` sets `no-cache` for JS/HTML; hard-reload once. |
| `_headers` seems ignored | It must sit in the deployed root (`dist/_headers`). Cloudflare supports up to 100 rules. |
| App works but demo buttons fail | `samples/` missing from the upload. |

---

## Re-deploying later

Route A: `npm run deploy:pages`
Route B: push to the connected branch.

## Removing it

Pages project → **Manage deployment** → **Delete project**, then remove the custom domain
and the DNS record it created.
