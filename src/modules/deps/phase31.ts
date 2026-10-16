import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { Finding } from '../../core/finding.js';
import { unifiedDiff } from '../../fixer/diff.js';
import { lockfileKind, withManifestOverride, type LockfileKind } from '../../fixer/override.js';
import {
  analyzeWorkflowTampering,
  analyzeWormIndicators,
  provenanceCoverage,
  type ProvenanceScore,
} from '../../supply/index.js';
import type { LockedPackage, LockfileGraph } from './lockfile.js';

function packageNameFromSnippet(snippet: string): string {
  if (snippet.startsWith('@')) {
    const second = snippet.indexOf('@', 1);
    return second === -1 ? snippet : snippet.slice(0, second);
  }
  const at = snippet.indexOf('@');
  return at <= 0 ? snippet : snippet.slice(0, at);
}

function parentsOf(name: string, edges: Map<string, Set<string>>): string[] {
  const out: string[] = [];
  for (const [from, tos] of edges) {
    if (tos.has(name)) out.push(from);
  }
  return out;
}

function isDirect(name: string, graph: LockfileGraph): boolean {
  return graph.directProd.has(name) || graph.directDev.has(name);
}

function packagesWithAFixedRelease(findings: readonly Finding[]): Set<string> {
  const names = new Set<string>();
  for (const finding of findings) {
    if (finding.ruleId !== 'DEPS-VULN-001' || finding.snippet === undefined) continue;
    if (!/Upgrade \S+ to \S+ or later/.test(finding.remediation)) continue;
    names.add(packageNameFromSnippet(finding.snippet));
  }
  return names;
}

function targetVersion(finding: Finding): string | undefined {
  const match = /Upgrade \S+ to (\S+) or later/.exec(finding.remediation);
  return match?.[1];
}

function kindFromLockfile(lockFile: string): LockfileKind {
  return lockfileKind(lockFile) ?? 'npm';
}

/** Unsafe npm/pnpm/yarn override when a vuln is transitive and the parent has no fixed release. */
export function attachOverrideProposals(
  findings: Finding[],
  graph: LockfileGraph,
  lockFile: string,
  manifestRaw: string | undefined,
): Finding[] {
  if (!graph.edgesKnown || manifestRaw === undefined) return findings;
  const withFix = packagesWithAFixedRelease(findings);
  const kind = kindFromLockfile(lockFile);
  return findings.map((finding) => {
    if (finding.ruleId !== 'DEPS-VULN-001' || finding.snippet === undefined) return finding;
    const name = packageNameFromSnippet(finding.snippet);
    if (name.length === 0 || isDirect(name, graph)) return finding;
    const version = targetVersion(finding);
    if (version === undefined) return finding;
    const parentFixed = parentsOf(name, graph.edges).some((parent) => withFix.has(parent));
    if (parentFixed) return finding;
    const after = withManifestOverride(manifestRaw, kind, name, version);
    const diff = unifiedDiff('package.json', manifestRaw, after);
    if (diff.length === 0) return finding;
    return {
      ...finding,
      fix: { kind: 'dependency-override', safe: false, diff },
    };
  });
}

function packageDir(cwd: string, pkg: LockedPackage): string | undefined {
  const candidates = [join(cwd, pkg.path), join(cwd, 'node_modules', pkg.name)];
  return candidates.find((dir) => existsSync(dir));
}

export function scanInstalledPackages(cwd: string, packages: readonly LockedPackage[]): Finding[] {
  const out: Finding[] = [];
  for (const pkg of packages) {
    const dir = packageDir(cwd, pkg);
    if (dir === undefined) continue;
    const prefix = pkg.path.startsWith('node_modules/') ? pkg.path : `node_modules/${pkg.name}`;
    for (const hit of [...analyzeWormIndicators(dir), ...analyzeWorkflowTampering(dir)]) {
      out.push({
        ...hit,
        file: hit.file !== undefined && hit.file.length > 0 ? `${prefix}/${hit.file}` : prefix,
      });
    }
  }
  return out;
}

export function loadProvenanceMap(cacheDir: string, packages: readonly LockedPackage[]): Map<string, boolean> {
  const known = new Map<string, boolean>();
  const root = join(cacheDir, 'provenance');
  if (!existsSync(root)) return known;
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    try {
      const raw = JSON.parse(readFileSync(join(root, `${key.replaceAll('/', '__')}.json`), 'utf8')) as {
        provenance?: unknown;
      };
      if (raw.provenance === true) known.set(key, true);
      else if (raw.provenance === false) known.set(key, false);
    } catch {
      // missing / unreadable attestations stay unknown (never guessed present)
    }
  }
  return known;
}

export function scoreProvenance(cacheDir: string, packages: readonly LockedPackage[]): ProvenanceScore {
  return provenanceCoverage(packages, loadProvenanceMap(cacheDir, packages));
}
