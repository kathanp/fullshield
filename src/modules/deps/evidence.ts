import type { Finding } from '../../core/finding.js';

export interface ReachabilityEvidence {
  imports: Array<{ file: string; line: number; specifier: string }>;
  calls?: Array<{ file: string; line: number; symbol: string }>;
  dependencyPath?: string[];
  reason: string;
}

export interface ImportSite {
  file: string;
  line: number;
  specifier: string;
  pkg: string;
}

const IMPORT_RE =
  /(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\))/g;

export function packageNameFromSpec(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return undefined;
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 0) return undefined;
    const rest = spec.slice(slash + 1);
    const cut = rest.indexOf('/');
    return cut === -1 ? spec : spec.slice(0, slash + 1 + cut);
  }
  const slash = spec.indexOf('/');
  return slash === -1 ? spec : spec.slice(0, slash);
}

/** Production import sites, at most the first five per package, file then line. */
export function collectImportSites(sources: ReadonlyMap<string, string>): Map<string, ImportSite[]> {
  const byPkg = new Map<string, ImportSite[]>();
  const files = [...sources.keys()].sort();
  for (const file of files) {
    const text = sources.get(file) ?? '';
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      IMPORT_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = IMPORT_RE.exec(line)) !== null) {
        const spec = match[1] ?? match[2] ?? match[3];
        if (spec === undefined) continue;
        const pkg = packageNameFromSpec(spec);
        if (pkg === undefined) continue;
        const list = byPkg.get(pkg) ?? [];
        list.push({ file, line: i + 1, specifier: spec, pkg });
        byPkg.set(pkg, list);
      }
    }
  }
  for (const [pkg, list] of byPkg) {
    list.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    byPkg.set(pkg, list.slice(0, 5));
  }
  return byPkg;
}

export function evidenceForFinding(
  finding: Finding,
  sites: ReadonlyMap<string, ImportSite[]>,
  productionFiles: readonly string[],
  edgesKnown: boolean,
): ReachabilityEvidence | undefined {
  if (finding.ruleId !== 'DEPS-VULN-001' && finding.ruleId !== 'DEPS-MALICIOUS-001') return undefined;
  const snippet = finding.snippet ?? '';
  const at = snippet.startsWith('@') ? snippet.indexOf('@', 1) : snippet.indexOf('@');
  const pkg = at <= 0 ? snippet : snippet.slice(0, at);
  if (pkg.length === 0) return undefined;
  const imports = (sites.get(pkg) ?? []).map((site) => ({
    file: site.file,
    line: site.line,
    specifier: site.specifier,
  }));
  const first = imports[0];
  const path = finding.dependencyPath;
  let reason: string;
  switch (finding.reachability) {
    case 'not-imported':
      reason = `No production file imports ${pkg}. Checked ${productionFiles.length} production file(s)${productionFiles.length > 0 ? `: ${productionFiles.slice(0, 8).join(', ')}` : ''}.`;
      return { imports: [], reason };
    case 'reachability-unknown':
      reason = edgesKnown
        ? `Reachability for ${pkg} is unknown.`
        : `Lockfile edges are missing, so ${pkg} is reachability-unknown.`;
      return { imports, ...(first !== undefined ? {} : {}), reason };
    case 'reachable-via-dependency':
      reason = path !== undefined && path.length > 0 ? `Required through ${path.join(' > ')}.` : `Required by an imported package.`;
      return { imports, ...(path !== undefined ? { dependencyPath: path } : {}), reason };
    case 'imported-not-called':
      reason = first !== undefined ? `Imported from ${first.file}:${first.line} and not called.` : `Imported and not called.`;
      return { imports, reason };
    case 'symbol-reachable':
      reason = first !== undefined ? `A named vulnerable export is called from ${first.file}:${first.line}.` : `A named vulnerable export is called.`;
      return { imports, reason };
    case 'symbol-not-called':
      reason = `A named vulnerable export is not called.`;
      return { imports, reason };
    default:
      reason = first !== undefined ? `Imported from ${first.file}:${first.line}.` : `Imported by production code.`;
      return { imports, ...(path !== undefined ? { dependencyPath: path } : {}), reason };
  }
}
