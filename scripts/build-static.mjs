/**
 * build-static.mjs - Copy only the browser-facing files into dist/.
 *
 * The repository also contains tools/cli.mjs and tools/mcp-server.mjs (Node processes with
 * filesystem and stdio access). Those must not be published to a public URL, so the deploy
 * uses this clean output folder instead of the repository root.
 *
 *   npm run build:static     -> dist/
 */

import { mkdirSync, cpSync, rmSync, statSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

const FILES = ['index.html', '_headers'];
const DIRS = ['assets', 'src', 'samples', 'image'];

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

for (const f of FILES) {
  const from = join(root, f);
  if (!statSync(from, { throwIfNoEntry: false })) { console.warn(`skip (missing): ${f}`); continue; }
  cpSync(from, join(dist, f));
}
for (const d of DIRS) cpSync(join(root, d), join(dist, d), { recursive: true });

const size = p => {
  const s = statSync(p);
  return s.isDirectory() ? readdirSync(p).reduce((n, f) => n + size(join(p, f)), 0) : s.size;
};
const kb = Math.round(size(dist) / 1024);

console.log(`dist/ ready (${kb} KB)`);
for (const e of readdirSync(dist)) console.log('  - ' + e);
