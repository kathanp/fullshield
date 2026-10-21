import { readFileSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { queryOsv, type QueryOsvOptions } from './osv.js';
import { osvSeverity } from './semver.js';

interface LibraryRow {
  package: string;
  banner?: string;
  version?: string;
}

function libraries(): LibraryRow[] {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      const raw = JSON.parse(readFileSync(join(dir, 'models', 'vendored.json'), 'utf8')) as { libraries?: unknown };
      if (!Array.isArray(raw.libraries)) {return [];}
      return raw.libraries.filter((row): row is LibraryRow => {
        if (typeof row !== 'object' || row === null) {return false;}
        const item = row as { package?: unknown };
        return typeof item.package === 'string';
      });
    } catch {
      const parent = dirname(dir);
      if (parent === dir) {break;}
      dir = parent;
    }
  }
  return [];
}

function isVendoredPath(rel: string): boolean {
  const norm = rel.replace(/\\/g, '/');
  return /(^|\/)(public|static|assets|vendor|lib)\//.test(norm) || norm.endsWith('.min.js');
}

const SKIP_DIRS = new Set(['node_modules', '.git', '.fullshield']);

/** Walker excludes `vendor/` and `*.min.js` by default. The flag reads those paths itself. */
async function vendoredPaths(cwd: string, files: readonly string[]): Promise<string[]> {
  const found = new Set(files.filter((rel) => isVendoredPath(rel)));
  async function walk(rel: string, depth: number): Promise<void> {
    if (depth > 6) {return;}
    let entries;
    try {
      entries = await readdir(join(cwd, rel), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) {continue;}
      const next = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) {
        await walk(next, depth + 1);
        continue;
      }
      if (entry.isFile() && isVendoredPath(next) && next.endsWith('.js')) {found.add(next);}
    }
  }
  await walk('', 0);
  return [...found].sort();
}

function captured(pattern: string | undefined, source: string): string | undefined {
  if (pattern === undefined) {return undefined;}
  try {
    const match = new RegExp(pattern).exec(source);
    const version = match?.[1];
    if (version === undefined || !/^\d+\.\d+\.\d+/.test(version)) {return undefined;}
    return version;
  } catch {
    return undefined;
  }
}

/** Banner or exported VERSION only. A miss is nothing; size and hash are never a version. */
export async function vendoredFindings(
  cwd: string,
  files: readonly string[],
  osv: QueryOsvOptions,
): Promise<Finding[]> {
  const rows = libraries();
  const out: Finding[] = [];
  for (const rel of await vendoredPaths(cwd, files)) {
    let source: string;
    try {
      source = await readFile(join(cwd, rel), 'utf8');
    } catch {
      continue;
    }
    for (const row of rows) {
      const version = captured(row.banner, source) ?? captured(row.version, source);
      if (version === undefined) {continue;}
      const hits = await queryOsv([{ name: row.package, version, path: rel }], osv);
      for (const hit of hits) {
        for (const vuln of hit.vulns) {
          const snippet = `${row.package}@${version}`;
          out.push({
            id: makeFindingId('DEPS-VENDORED-001', rel, `${snippet}|${vuln.id}`),
            ruleId: 'DEPS-VENDORED-001',
            module: 'deps',
            title: `Vendored ${snippet}`,
            severity: osvSeverity(vuln),
            confidence: 'high',
            file: rel,
            snippet,
            message: `${rel} matches ${snippet}, which OSV lists as ${vuln.id}.`,
            remediation: `Replace ${rel}. Do not edit the vendored file in place.`,
            references: [vuln.id],
            reachability: 'vendored',
          });
        }
      }
    }
  }
  return out;
}
