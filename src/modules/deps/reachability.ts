import { severityRank, SEVERITIES, type Finding, type Severity } from '../../core/finding.js';
import type { LockfileGraph } from './lockfile.js';

export type Reachability = NonNullable<Finding['reachability']>;

export interface PackageUsage {
  imported: boolean;
  called: boolean;
}

export interface ReachabilityContext {
  /** Imports from production sources only (not test/spec files). */
  productionUsage: Map<string, PackageUsage>;
  graph: LockfileGraph;
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
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return undefined;
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
  if (/(^|\/)(__tests__|tests|test)(\/|$)/.test(n)) return false;
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(n)) return false;
  return true;
}

/** Best-effort: which npm packages the scanned sources import and call. */
export function indexPackageUsage(sources: ReadonlyMap<string, string>): Map<string, PackageUsage> {
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

  for (const source of sources.values()) {
    for (const re of [nsRe, importRe, importStarRe]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(source)) !== null) {
        const local = m[1];
        const spec = m[2];
        if (local === undefined || spec === undefined) continue;
        const pkg = packageNameFromSpec(spec);
        if (pkg === undefined) continue;
        bump(pkg, localIsCalled(source, local));
      }
    }
    namedRe.lastIndex = 0;
    let named: RegExpExecArray | null;
    while ((named = namedRe.exec(source)) !== null) {
      const spec = named[2];
      if (spec === undefined) continue;
      const pkg = packageNameFromSpec(spec);
      if (pkg === undefined) continue;
      const locals = (named[1] ?? '').split(',').map((s) => s.trim().split(/\s+as\s+/).pop() ?? '');
      bump(
        pkg,
        locals.some((local) => local.length > 0 && localIsCalled(source, local)),
      );
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
    if (path === undefined) continue;
    const last = path[path.length - 1];
    if (last === undefined) continue;
    if (last === target) return path;
    for (const next of edges.get(last) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push([...path, next]);
    }
  }
  return undefined;
}

function reachableFrom(target: string, roots: Set<string>, edges: Map<string, Set<string>>): boolean {
  if (roots.has(target)) return true;
  return shortestDependencyPath(target, roots, edges) !== undefined;
}

function importedDirectNames(usage: Map<string, PackageUsage>, graph: LockfileGraph): Set<string> {
  const directs = new Set([...graph.directProd, ...graph.directDev]);
  const out = new Set<string>();
  for (const [name, hit] of usage) {
    if (!hit.imported) continue;
    if (directs.size === 0 || directs.has(name)) out.add(name);
  }
  return out;
}

export function classifyReachability(
  pkgName: string,
  productionUsage: Map<string, PackageUsage>,
  graph?: LockfileGraph,
): { reachability: Reachability; path?: string[] } {
  const hit = productionUsage.get(pkgName);
  if (hit?.imported === true) {
    return { reachability: hit.called ? 'reachable' : 'imported-not-called' };
  }
  if (graph !== undefined && graph.edgesKnown) {
    const roots = importedDirectNames(productionUsage, graph);
    const path = shortestDependencyPath(pkgName, roots, graph.edges);
    if (path !== undefined && path.length >= 2) {
      return { reachability: 'reachable-via-dependency', path };
    }
    return { reachability: 'not-imported' };
  }
  if (graph !== undefined && !graph.edgesKnown) {
    return { reachability: 'reachability-unknown' };
  }
  return { reachability: 'not-imported' };
}

/**
 * reachable-via-dependency keeps OSV severity: the parent that the app
 * imports loads this package. imported-not-called is −1; not-imported is −2.
 */
export function reachabilitySteps(reachability: Reachability): number {
  if (
    reachability === 'reachable' ||
    reachability === 'reachable-via-dependency' ||
    reachability === 'reachability-unknown'
  ) {
    return 0;
  }
  if (reachability === 'imported-not-called') return 1;
  return 2;
}

export function downgradeSeverity(severity: Severity, steps: number): Severity {
  const next = Math.max(0, severityRank(severity) - steps);
  return SEVERITIES[next] ?? 'info';
}

function isDevOnly(pkgName: string, ctx: ReachabilityContext): boolean {
  if (ctx.productionUsage.get(pkgName)?.imported === true) return false;
  const { directProd, directDev, edges, edgesKnown } = ctx.graph;
  if (!edgesKnown) {
    return directDev.has(pkgName) && !directProd.has(pkgName);
  }
  const inProd = reachableFrom(pkgName, directProd, edges);
  if (inProd) return false;
  return directDev.has(pkgName) || reachableFrom(pkgName, directDev, edges);
}

export function applyReachability(findings: Finding[], ctx: ReachabilityContext): Finding[] {
  return findings.map((finding) => {
    if (finding.ruleId === 'DEPS-MALICIOUS-001') {
      if (finding.snippet === undefined) return finding;
      const pkg = packageNameFromSnippet(finding.snippet);
      if (pkg === undefined || pkg.length === 0) return finding;
      const classified = classifyReachability(pkg, ctx.productionUsage, ctx.graph);
      return {
        ...finding,
        severity: 'critical',
        reachability: classified.reachability,
        ...(classified.path !== undefined ? { dependencyPath: classified.path } : {}),
      };
    }
    if (finding.ruleId !== 'DEPS-VULN-001' || finding.snippet === undefined) return finding;
    const pkg = packageNameFromSnippet(finding.snippet);
    if (pkg === undefined || pkg.length === 0) return finding;
    const classified = classifyReachability(pkg, ctx.productionUsage, ctx.graph);
    const steps = reachabilitySteps(classified.reachability);
    let severity = steps === 0 ? finding.severity : downgradeSeverity(finding.severity, steps);
    let message = finding.message;
    if (classified.path !== undefined) {
      const shown = classified.path.join(' > ');
      message = `${message} Reachable via ${shown}.`;
    }
    const devOnly = isDevOnly(pkg, ctx);
    if (devOnly) {
      severity = 'info';
      message = `${message} (dev-only)`;
    }
    return {
      ...finding,
      reachability: classified.reachability,
      ...(classified.path !== undefined ? { dependencyPath: classified.path } : {}),
      severity,
      message,
    };
  });
}
