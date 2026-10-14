import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { parseLockfileGraph, type LockedPackage, type LockfileGraph } from './lockfile.js';
import { isMaliciousAdvisory, queryOsv, type OsvVuln } from './osv.js';
import { exactPinsFromManifest } from './pins.js';
import { applyReachability, indexPackageUsage, isProductionSource } from './reachability.js';
import { minFixedVersion, osvSeverity, sameMajor } from './semver.js';
import { findTyposquats, type TyposquatHit } from './typosquat.js';

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

function defaultCacheDir(): string {
  return join(homedir(), '.cache', 'fullshield');
}

const MANIFEST_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

async function readDirectDependencyNames(cwd: string): Promise<Set<string> | undefined> {
  try {
    const raw = await readFile(join(cwd, 'package.json'), 'utf8');
    const pkg = JSON.parse(raw) as Record<string, unknown>;
    const names = new Set<string>();
    for (const field of MANIFEST_FIELDS) {
      const block = pkg[field];
      if (block !== null && typeof block === 'object' && !Array.isArray(block)) {
        for (const name of Object.keys(block)) names.add(name);
      }
    }
    return names;
  } catch {
    return undefined;
  }
}

function vulnFinding(lockFile: string, pkg: LockedPackage, vuln: OsvVuln): Finding {
  const snippet = `${pkg.name}@${pkg.version}`;
  const aliases = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-'));
  const references = [vuln.id, ...aliases];
  const summary = vuln.summary ?? 'known vulnerability';
  const fixed = minFixedVersion(vuln.affected ?? []);
  const finding: Finding = {
    id: makeFindingId('DEPS-VULN-001', lockFile, `${snippet}|${vuln.id}`),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: `Vulnerable dependency ${snippet}`,
    severity: osvSeverity(vuln),
    confidence: 'high',
    file: lockFile,
    snippet,
    message: `${snippet} is affected by ${vuln.id} (${summary}).`,
    remediation: fixed
      ? `Upgrade ${pkg.name} to ${fixed} or later (data from OSV).`
      : `Upgrade ${pkg.name} to a version that OSV does not mark as affected.`,
    references,
  };
  if (fixed !== undefined) {
    finding.fix = {
      kind: 'dependency-bump',
      safe: sameMajor(pkg.version, fixed),
      diff: `--- a/package.json\n+++ b/package.json\n# bump ${pkg.name} from ${pkg.version} to ${fixed}\n`,
    };
  }
  return finding;
}

const MALICIOUS_REMEDIATION =
  'Remove the package from package.json and the lockfile, delete node_modules, reinstall, and rotate any credentials on machines that installed it. Install scripts run at npm install regardless of whether application code imports the package.';

function maliciousFinding(lockFile: string, pkg: LockedPackage, vuln: OsvVuln): Finding {
  const snippet = `${pkg.name}@${pkg.version}`;
  return {
    id: makeFindingId('DEPS-MALICIOUS-001', lockFile, `${snippet}|${vuln.id}`),
    ruleId: 'DEPS-MALICIOUS-001',
    module: 'deps',
    title: `Malicious dependency ${snippet}`,
    severity: 'critical',
    confidence: 'high',
    file: lockFile,
    snippet,
    message: `${snippet} is flagged malicious by OSV (${vuln.id}${vuln.summary ? `: ${vuln.summary}` : ''}).`,
    remediation: MALICIOUS_REMEDIATION,
    references: [vuln.id, ...(vuln.aliases ?? [])],
  };
}

function typosquatFinding(lockFile: string, hit: TyposquatHit): Finding {
  const snippet = `${hit.name}@${hit.version}`;
  return {
    id: makeFindingId('DEPS-TYPOSQUAT-001', lockFile, snippet),
    ruleId: 'DEPS-TYPOSQUAT-001',
    module: 'deps',
    title: `Possible typosquat: ${hit.name}`,
    severity: 'medium',
    confidence: 'low',
    file: lockFile,
    snippet,
    message: `Package "${hit.name}" is 1 character from popular package "${hit.lookalike}" (possible typosquat).`,
    remediation: `Confirm you intended to install "${hit.name}". If not, remove it and depend on "${hit.lookalike}" instead.`,
  };
}

function noLockFinding(): Finding {
  return {
    id: makeFindingId('DEPS-NOLOCK-001', 'package.json', 'no-lockfile'),
    ruleId: 'DEPS-NOLOCK-001',
    module: 'deps',
    title: 'No lockfile found',
    severity: 'info',
    confidence: 'high',
    file: 'package.json',
    message: 'No lockfile found; dependency vulnerabilities were not checked.',
    remediation:
      'Commit package-lock.json, pnpm-lock.yaml, or yarn.lock so FullShield can audit the installed tree. Exact versions pinned in package.json are still queried.',
  };
}

function deprecatedFinding(lockFile: string, pkg: LockedPackage): Finding {
  const snippet = `${pkg.name}@${pkg.version}`;
  return {
    id: makeFindingId('DEPS-DEPRECATED-001', lockFile, snippet),
    ruleId: 'DEPS-DEPRECATED-001',
    module: 'deps',
    title: `Deprecated dependency ${snippet}`,
    severity: 'info',
    confidence: 'high',
    file: lockFile,
    snippet,
    message: `${snippet} is marked deprecated in the lockfile${
      pkg.deprecated !== undefined ? `: ${pkg.deprecated}` : '.'
    }`,
    remediation: `Replace ${pkg.name} with a maintained alternative.`,
  };
}

export const depsModule: ScanModule = {
  name: 'deps',
  async run(ctx) {
    const lockFile = LOCKFILE_NAMES.find((name) => ctx.files.includes(name));
    const cacheDir =
      ctx.config.deps.cacheDir !== undefined
        ? resolve(ctx.cwd, ctx.config.deps.cacheDir)
        : defaultCacheDir();
    const osvOpts = { cacheDir, offline: ctx.config.deps.offline };

    if (lockFile === undefined) {
      if (!ctx.files.includes('package.json')) return [];
      const findings: Finding[] = [noLockFinding()];
      let manifest: Record<string, unknown> = {};
      try {
        manifest = JSON.parse(await readFile(join(ctx.cwd, 'package.json'), 'utf8')) as Record<
          string,
          unknown
        >;
      } catch {
        return findings;
      }
      const pins = exactPinsFromManifest(manifest);
      const directNames = await readDirectDependencyNames(ctx.cwd);
      for (const hit of findTyposquats(pins, { directNames })) {
        findings.push(typosquatFinding('package.json', hit));
      }
      const osvHits = await queryOsv(pins, osvOpts);
      for (const hit of osvHits) {
        for (const vuln of hit.vulns) {
          findings.push(
            isMaliciousAdvisory(vuln)
              ? maliciousFinding('package.json', hit.pkg, vuln)
              : vulnFinding('package.json', hit.pkg, vuln),
          );
        }
      }
      return applyReachability(findings, await reachabilityCtx(ctx.cwd, ctx.files, graphFromManifest(manifest)));
    }

    let contents: string;
    try {
      contents = await readFile(join(ctx.cwd, lockFile), 'utf8');
    } catch {
      return [];
    }

    const graph = parseLockfileGraph(lockFile, contents);
    const packages = graph.packages;
    const findings: Finding[] = [];
    const directNames = await readDirectDependencyNames(ctx.cwd);

    for (const hit of findTyposquats(packages, { directNames })) {
      findings.push(typosquatFinding(lockFile, hit));
    }
    for (const pkg of packages) {
      if (pkg.deprecated !== undefined) {
        findings.push(deprecatedFinding(lockFile, pkg));
      }
    }

    const osvHits = await queryOsv(packages, osvOpts);
    for (const hit of osvHits) {
      for (const vuln of hit.vulns) {
        findings.push(
          isMaliciousAdvisory(vuln)
            ? maliciousFinding(lockFile, hit.pkg, vuln)
            : vulnFinding(lockFile, hit.pkg, vuln),
        );
      }
    }
    return applyReachability(findings, await reachabilityCtx(ctx.cwd, ctx.files, graph));
  },
};

function graphFromManifest(manifest: Record<string, unknown>): LockfileGraph {
  const keys = (field: string): Set<string> => {
    const block = manifest[field];
    if (block !== null && typeof block === 'object' && !Array.isArray(block)) {
      return new Set(Object.keys(block));
    }
    return new Set();
  };
  return {
    packages: [],
    edges: new Map(),
    directProd: keys('dependencies'),
    directDev: keys('devDependencies'),
    edgesKnown: false,
  };
}

async function reachabilityCtx(
  cwd: string,
  files: readonly string[],
  graph: LockfileGraph,
): Promise<{ productionUsage: Map<string, { imported: boolean; called: boolean }>; graph: LockfileGraph }> {
  const prodSources = new Map<string, string>();
  for (const rel of files) {
    if (!/\.[cm]?[jt]sx?$/.test(rel)) continue;
    if (!isProductionSource(rel)) continue;
    try {
      prodSources.set(rel, await readFile(join(cwd, rel), 'utf8'));
    } catch {
      // skip
    }
  }
  return { productionUsage: indexPackageUsage(prodSources), graph };
}
