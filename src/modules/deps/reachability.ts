import { severityRank, SEVERITIES, type Finding, type Severity } from '../../core/finding.js';

export type Reachability = NonNullable<Finding['reachability']>;

export interface PackageUsage {
  imported: boolean;
  called: boolean;
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

export function classifyReachability(pkgName: string, usage: Map<string, PackageUsage>): Reachability {
  const hit = usage.get(pkgName);
  if (hit === undefined || !hit.imported) return 'not-imported';
  return hit.called ? 'reachable' : 'imported-not-called';
}

export function downgradeSeverity(severity: Severity, steps: number): Severity {
  const next = Math.max(0, severityRank(severity) - steps);
  return SEVERITIES[next] ?? 'info';
}

export function applyReachability(findings: Finding[], usage: Map<string, PackageUsage>): Finding[] {
  return findings.map((finding) => {
    if (finding.ruleId !== 'DEPS-VULN-001' || finding.snippet === undefined) return finding;
    const pkg = packageNameFromSnippet(finding.snippet);
    if (pkg === undefined || pkg.length === 0) return finding;
    const reachability = classifyReachability(pkg, usage);
    const steps = reachability === 'reachable' ? 0 : reachability === 'imported-not-called' ? 1 : 2;
    return {
      ...finding,
      reachability,
      severity: steps === 0 ? finding.severity : downgradeSeverity(finding.severity, steps),
    };
  });
}
