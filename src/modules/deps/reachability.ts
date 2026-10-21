import { makeFindingId, severityRank, SEVERITIES, type Finding, type Severity } from '../../core/finding.js';
import type { LockfileGraph } from './lockfile.js';
import { classifySymbolUse } from './symbol-reachability.js';

export type Reachability = NonNullable<Finding['reachability']>;

export interface PackageUsage {
  imported: boolean;
  called: boolean;
}

export interface ReachabilityContext {
  /** Imports from production sources only (not test/spec files). */
  productionUsage: Map<string, PackageUsage>;
  graph: LockfileGraph;
  /** Production sources, used only when an advisory names affected functions. */
  sources?: ReadonlyMap<string, string>;
}

/** `name@version` or `@scope/name@version` from a DEPS-VULN-001 snippet. */
function packageNameFromSnippet(snippet: string): string | undefined {
  if (snippet.startsWith('@')) {
    const second = snippet.indexOf('@', 1);
    return second === -1 ? snippet : snippet.slice(0, second);
  }
  const at = snippet.indexOf('@');
  return at <= 0 ? snippet : snippet.slice(0, at);
}

function packageNameFromSpec(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {return undefined;}
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : spec;
  }
  return spec.split('/')[0];
}

function localIsCalled(source: string, local: string): boolean {
  const re = new RegExp(`\\b${local.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[.(]`);
  return re.test(source);
}

export function isProductionSource(rel: string): boolean {
  const n = rel.replace(/\\/g, '/');
  if (/(^|\/)(__tests__|tests|test)(\/|$)/.test(n)) {return false;}
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(n)) {return false;}
  return true;
}

/** Packages one source file imports and calls. */
export function usageInSource(source: string): Map<string, PackageUsage> {
  const usage = new Map<string, PackageUsage>();
  const bump = (pkg: string, called: boolean): void => {
    const prev = usage.get(pkg) ?? { imported: false, called: false };
    usage.set(pkg, { imported: true, called: prev.called || called });
  };

  const nsRe =
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;
  const namedRe =
    /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;
  const importRe = /import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/g;
  const importStarRe = /import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/g;

  for (const re of [nsRe, importRe, importStarRe]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      const local = m[1];
      const spec = m[2];
      if (local === undefined || spec === undefined) {continue;}
      const pkg = packageNameFromSpec(spec);
      if (pkg === undefined) {continue;}
      bump(pkg, localIsCalled(source, local));
    }
  }
  namedRe.lastIndex = 0;
  let named: RegExpExecArray | null;
  while ((named = namedRe.exec(source)) !== null) {
    const spec = named[2];
    if (spec === undefined) {continue;}
    const pkg = packageNameFromSpec(spec);
    if (pkg === undefined) {continue;}
    const locals = (named[1] ?? '').split(',').map((s) => s.trim().split(/\s+as\s+/).pop() ?? '');
    bump(
      pkg,
      locals.some((local) => local.length > 0 && localIsCalled(source, local)),
    );
  }
  return usage;
}

/** Best-effort: which npm packages the scanned sources import and call. */
export function indexPackageUsage(sources: ReadonlyMap<string, string>): Map<string, PackageUsage> {
  const usage = new Map<string, PackageUsage>();
  for (const source of sources.values()) {
    for (const [pkg, row] of usageInSource(source)) {
      const prev = usage.get(pkg) ?? { imported: false, called: false };
      usage.set(pkg, { imported: true, called: prev.called || row.called });
    }
  }
  return usage;
}

/** Shortest lockfile path from any `starts` name to `target`, inclusive. */
export function shortestDependencyPath(
  target: string,
  starts: Iterable<string>,
  edges: Map<string, Set<string>>,
): string[] | undefined {
  const queue: string[][] = [];
  const seen = new Set<string>();
  for (const start of starts) {
    queue.push([start]);
    seen.add(start);
  }
  while (queue.length > 0) {
    const path = queue.shift();
    if (path === undefined) {continue;}
    const last = path[path.length - 1];
    if (last === undefined) {continue;}
    if (last === target) {return path;}
    for (const next of edges.get(last) ?? []) {
      if (seen.has(next)) {continue;}
      seen.add(next);
      queue.push([...path, next]);
    }
  }
  return undefined;
}

/** Up to `limit` dependency paths, shortest first. Bounded so a wide tree cannot explode. */
export function collectDependencyPaths(
  target: string,
  starts: Iterable<string>,
  edges: Map<string, Set<string>>,
  limit = 8,
): string[][] {
  const out: string[][] = [];
  const queue: string[][] = [];
  let steps = 0;
  for (const start of starts) {queue.push([start]);}
  while (queue.length > 0 && out.length < limit && steps < 4000) {
    steps += 1;
    const path = queue.shift();
    if (path === undefined) {continue;}
    const last = path[path.length - 1];
    if (last === undefined) {continue;}
    if (last === target) {
      if (path.length >= 2) {out.push(path);}
      continue;
    }
    if (path.length >= 12) {continue;}
    for (const next of edges.get(last) ?? []) {
      if (path.includes(next)) {continue;}
      queue.push([...path, next]);
    }
  }
  return out;
}

function reachableFrom(target: string, roots: Set<string>, edges: Map<string, Set<string>>): boolean {
  if (roots.has(target)) {return true;}
  return shortestDependencyPath(target, roots, edges) !== undefined;
}

function importedDirectNames(usage: Map<string, PackageUsage>, graph: LockfileGraph): Set<string> {
  const directs = new Set([...graph.directProd, ...graph.directDev]);
  const out = new Set<string>();
  for (const [name, hit] of usage) {
    if (!hit.imported) {continue;}
    if (directs.size === 0 || directs.has(name)) {out.add(name);}
  }
  return out;
}

export function classifyReachability(
  pkgName: string,
  productionUsage: Map<string, PackageUsage>,
  graph?: LockfileGraph,
): { reachability: Reachability; path?: string[]; paths?: string[][] } {
  const hit = productionUsage.get(pkgName);
  if (hit?.imported === true) {
    return { reachability: hit.called ? 'reachable' : 'imported-not-called' };
  }
  if (graph !== undefined && graph.edgesKnown) {
    const roots = importedDirectNames(productionUsage, graph);
    const paths = collectDependencyPaths(pkgName, roots, graph.edges);
    paths.sort((a, b) => a.length - b.length || a.join('>').localeCompare(b.join('>')));
    const path = paths[0];
    if (path !== undefined && path.length >= 2) {
      return { reachability: 'reachable-via-dependency', path, paths };
    }
    return { reachability: 'not-imported' };
  }
  if (graph !== undefined && !graph.edgesKnown) {
    return { reachability: 'reachability-unknown' };
  }
  return { reachability: 'not-imported' };
}

/**
 * Direct production dependencies that no project file imports and that no
 * imported package requires. Imported and imported-not-called names stay out.
 * When the lockfile has no edges, the list is empty.
 */
export function unusedDirectPackages(ctx: ReachabilityContext): string[] {
  if (!ctx.graph.edgesKnown) {return [];}
  const imported = importedDirectNames(ctx.productionUsage, ctx.graph);
  return [...ctx.graph.directProd]
    .filter((name) => {
      if (ctx.productionUsage.get(name)?.imported === true) {return false;}
      return !reachableFrom(name, imported, ctx.graph.edges);
    })
    .sort();
}

export function unusedDirectPlan(
  findings: readonly Finding[],
  ctx: ReachabilityContext,
): { packages: string[]; advisories: number } | undefined {
  const packages = unusedDirectPackages(ctx);
  if (packages.length === 0) {return undefined;}
  const names = new Set(packages);
  let advisories = 0;
  for (const finding of findings) {
    if (finding.ruleId !== 'DEPS-VULN-001' && finding.ruleId !== 'DEPS-MALICIOUS-001') {continue;}
    if (finding.snippet === undefined) {continue;}
    const pkg = packageNameFromSnippet(finding.snippet);
    if (pkg !== undefined && names.has(pkg)) {advisories += 1;}
  }
  return { packages, advisories };
}

/**
 * reachable-via-dependency keeps OSV severity: the parent that the app
 * imports loads this package. imported-not-called is −1; not-imported is −2.
 */
export function reachabilitySteps(reachability: Reachability): number {
  if (
    reachability === 'reachable' ||
    reachability === 'reachable-via-dependency' ||
    reachability === 'reachability-unknown' ||
    reachability === 'symbol-reachable'
  ) {
    return 0;
  }
  if (reachability === 'imported-not-called' || reachability === 'symbol-not-called') {return 1;}
  return 2;
}

export function downgradeSeverity(severity: Severity, steps: number): Severity {
  const next = Math.max(0, severityRank(severity) - steps);
  return SEVERITIES[next] ?? 'info';
}

function isDevOnly(pkgName: string, ctx: ReachabilityContext): boolean {
  if (ctx.productionUsage.get(pkgName)?.imported === true) {return false;}
  const { directProd, directDev, edges, edgesKnown } = ctx.graph;
  if (!edgesKnown) {
    return directDev.has(pkgName) && !directProd.has(pkgName);
  }
  const inProd = reachableFrom(pkgName, directProd, edges);
  if (inProd) {return false;}
  return directDev.has(pkgName) || reachableFrom(pkgName, directDev, edges);
}

const REACH_RANK: Record<Reachability, number> = {
  reachable: 0,
  'symbol-reachable': 1,
  'reachable-via-dependency': 2,
  'imported-not-called': 3,
  'symbol-not-called': 4,
  'reachability-unknown': 5,
  'not-imported': 6,
  vendored: 0,
};

function versionFromSnippet(snippet: string): string {
  const name = packageNameFromSnippet(snippet);
  if (name === undefined) {return snippet;}
  return snippet.slice(name.length + 1);
}

function pathFields(classified: { path?: string[]; paths?: string[][] }): {
  dependencyPath?: string[];
  dependencyPaths?: string[][];
} {
  const paths = classified.paths ?? (classified.path !== undefined ? [classified.path] : []);
  if (paths.length === 0) {return {};}
  return {
    dependencyPath: paths[0],
    ...(paths.length > 1 ? { dependencyPaths: paths } : {}),
  };
}

function appendOtherPaths(message: string, paths: string[][] | undefined): string {
  if (paths === undefined || paths.length < 2) {return message;}
  const rest = paths.slice(1).map((p) => p.join(' > ')).sort().join('; ');
  return `${message} Other paths: ${rest}.`;
}

/** One finding per package name + advisory. Versions and paths are listed on that finding. */
export function groupPackageAdvisories(findings: readonly Finding[]): Finding[] {
  const passthrough: Finding[] = [];
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (finding.ruleId !== 'DEPS-VULN-001' && finding.ruleId !== 'DEPS-MALICIOUS-001') {
      passthrough.push(finding);
      continue;
    }
    const name = packageNameFromSnippet(finding.snippet ?? '') ?? finding.snippet ?? finding.id;
    const advisory = finding.references?.[0] ?? finding.id;
    const key = `${finding.ruleId}\0${name}\0${advisory}`;
    const list = groups.get(key);
    if (list === undefined) {groups.set(key, [finding]);}
    else {list.push(finding);}
  }
  const merged: Finding[] = [];
  for (const list of groups.values()) {
    const only = list[0];
    if (list.length === 1 && only !== undefined) {
      merged.push(only);
      continue;
    }
    merged.push(mergeAdvisory(list));
  }
  return [...passthrough, ...merged];
}

function mergeAdvisory(list: readonly Finding[]): Finding {
  const ranked = [...list].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (REACH_RANK[a.reachability ?? 'not-imported'] ?? 9) - (REACH_RANK[b.reachability ?? 'not-imported'] ?? 9),
  );
  const primary = ranked[0];
  if (primary === undefined) {
    throw new Error('empty advisory group');
  }
  const name = packageNameFromSnippet(primary.snippet ?? '') ?? 'package';
  const versions = [...new Set(list.map((f) => versionFromSnippet(f.snippet ?? '')))].filter((v) => v.length > 0).sort();
  const paths: string[][] = [];
  const seenPath = new Set<string>();
  for (const finding of list) {
    const candidates = finding.dependencyPaths ?? (finding.dependencyPath !== undefined ? [finding.dependencyPath] : []);
    for (const path of candidates) {
      const key = path.join('\0');
      if (seenPath.has(key)) {continue;}
      seenPath.add(key);
      paths.push(path);
    }
  }
  paths.sort((a, b) => a.length - b.length || a.join('>').localeCompare(b.join('>')));
  const advisory = primary.references?.[0] ?? '';
  const onManifest = list.find((f) => f.file === 'package.json');
  const file = onManifest?.file ?? primary.file;
  const line = onManifest?.line ?? primary.line;
  const snippet = versions.length > 0 ? `${name}@${versions.join(',')}` : (primary.snippet ?? name);
  let message = primary.message;
  if (versions.length > 1) {
    message = `${message} Versions: ${versions.join(', ')}.`;
  }
  if (paths.length > 1) {
    message = `${message} Dependency paths: ${paths.map((p) => p.join(' > ')).join('; ')}.`;
  }
  return {
    ...primary,
    id: makeFindingId(primary.ruleId, file, `${name}|${advisory}|${versions.join(',')}`),
    file,
    line,
    snippet,
    message,
    severity: primary.severity,
    reachability: primary.reachability,
    ...(paths[0] !== undefined ? { dependencyPath: paths[0] } : {}),
    ...(paths.length > 1 ? { dependencyPaths: paths } : {}),
  };
}

export function applyReachability(
  findings: Finding[],
  ctx: ReachabilityContext,
  symbols: ReadonlyMap<string, readonly string[]> = new Map(),
): Finding[] {
  const mapped: Finding[] = findings.map((finding): Finding => {
    if (finding.ruleId === 'DEPS-MALICIOUS-001') {
      // Symbol data never downgrades a malicious advisory. Severity stays critical.
      if (finding.snippet === undefined) {return finding;}
      const pkg = packageNameFromSnippet(finding.snippet);
      if (pkg === undefined || pkg.length === 0) {return finding;}
      const classified = classifyReachability(pkg, ctx.productionUsage, ctx.graph);
      return {
        ...finding,
        severity: 'critical',
        reachability: classified.reachability,
        ...pathFields(classified),
      };
    }
    if (finding.ruleId !== 'DEPS-VULN-001' || finding.snippet === undefined) {return finding;}
    const pkg = packageNameFromSnippet(finding.snippet);
    if (pkg === undefined || pkg.length === 0) {return finding;}
    let classified = classifyReachability(pkg, ctx.productionUsage, ctx.graph);
    const named = symbols.get(finding.id) ?? [];
    if (named.length > 0 && ctx.sources !== undefined) {
      const symbolClass = classifySymbolUse(named, ctx.sources);
      classified = { reachability: symbolClass, path: classified.path, paths: classified.paths };
    }
    const steps = reachabilitySteps(classified.reachability);
    let severity = steps === 0 ? finding.severity : downgradeSeverity(finding.severity, steps);
    let message = finding.message;
    if (classified.path !== undefined) {
      const shown = classified.path.join(' > ');
      message = `${message} Reachable via ${shown}.`;
      message = appendOtherPaths(message, classified.paths);
    }
    const devOnly = isDevOnly(pkg, ctx);
    if (devOnly) {
      severity = 'info';
      message = `${message} (dev-only)`;
    }
    return {
      ...finding,
      reachability: classified.reachability,
      ...pathFields(classified),
      severity,
      message,
    };
  });
  return groupPackageAdvisories(mapped);
}
