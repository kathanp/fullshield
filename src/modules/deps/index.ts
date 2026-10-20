import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { parseLockfileGraph, type LockedPackage, type LockfileGraph } from './lockfile.js';
import { isMaliciousAdvisory, queryOsv, type OsvVuln } from './osv.js';
import { exactPinsFromManifest, lineOfManifestDep } from './pins.js';
import { collectImportSites, evidenceForFinding } from './evidence.js';
import { dependencyShapeFindings } from './phantom.js';
import { callGraphConfigHash, indexPackageUsageCached } from './call-graph-cache.js';
import { applyReachability, indexPackageUsage, isProductionSource, unusedDirectPlan } from './reachability.js';
import { perf2Enabled } from '../../core/perf2.js';
import { chooseUpgradePlan, type UpgradeAdvisory } from './upgrade-plan.js';
import { campaignFindings, securityPlaceholderFinding } from '../../supply/campaign.js';
import { affectedFunctionNames } from './symbol-reachability.js';
import { minFixedVersion, osvSeverity, sameMajor } from './semver.js';
import { findTyposquats, type TyposquatHit } from './typosquat.js';
import { experimentalVex } from '../../supply/experimental.js';
import { licenseEnabled } from '../sast/experimental.js';
import { scanCopyleftLicenses } from './license.js';
import { attachOverrideProposals, scanInstalledPackages } from './phase31.js';
import { provenanceEnabled, provenanceFindingsForScan } from '../../provenance/index.js';
import { capabilitiesEnabled, capabilityFindings } from '../../capabilities/index.js';

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

function vulnFinding(
  lockFile: string,
  pkg: LockedPackage,
  vuln: OsvVuln,
  loc?: { file: string; line?: number },
): Finding {
  const snippet = `${pkg.name}@${pkg.version}`;
  const aliases = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-'));
  const references = [vuln.id, ...aliases];
  const summary = vuln.summary ?? 'known vulnerability';
  const fixed = minFixedVersion(vuln.affected ?? []);
  const file = loc?.file ?? lockFile;
  const finding: Finding = {
    id: makeFindingId('DEPS-VULN-001', file, `${snippet}|${vuln.id}`),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: `Vulnerable dependency ${snippet}`,
    severity: osvSeverity(vuln),
    confidence: 'high',
    file,
    line: loc?.line,
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

export const depsModule: ScanModule & {
  unusedDirect?: { packages: string[]; advisories: number };
  upgradePlan?: { bumps: Array<{ name: string; from: string; to: string; safe: boolean; findings: number }>; unresolved: string[]; sentence: string };
} = {
  name: 'deps',
  async run(ctx) {
    depsModule.unusedDirect = undefined;
    depsModule.upgradePlan = undefined;
    const lockFile = LOCKFILE_NAMES.find((name) => ctx.files.includes(name));
    const cacheDir =
      ctx.config.deps.cacheDir !== undefined
        ? resolve(ctx.cwd, ctx.config.deps.cacheDir)
        : defaultCacheDir();
    const osvOpts = { cacheDir, offline: ctx.config.deps.offline };

    let manifestRaw: string | undefined;
    try {
      manifestRaw = await readFile(join(ctx.cwd, 'package.json'), 'utf8');
    } catch {
      manifestRaw = undefined;
    }
    const depLoc = (name: string): { file: string; line?: number } | undefined => {
      if (manifestRaw === undefined) return undefined;
      const line = lineOfManifestDep(manifestRaw, name);
      return line === undefined ? undefined : { file: 'package.json', line };
    };

    if (lockFile === undefined) {
      if (!ctx.files.includes('package.json')) return [];
      const findings: Finding[] = [noLockFinding()];
      let manifest: Record<string, unknown> = {};
      try {
        manifest = JSON.parse(manifestRaw ?? '{}') as Record<string, unknown>;
      } catch {
        return findings;
      }
      const pins = exactPinsFromManifest(manifest);
      const directNames = await readDirectDependencyNames(ctx.cwd);
      for (const hit of findTyposquats(pins, { directNames })) {
        findings.push(typosquatFinding('package.json', hit));
      }
      const osvHits = await queryOsv(pins, osvOpts);
      const symbols = new Map<string, readonly string[]>();
      for (const hit of osvHits) {
        for (const vuln of hit.vulns) {
          const finding = isMaliciousAdvisory(vuln)
            ? maliciousFinding('package.json', hit.pkg, vuln)
            : vulnFinding('package.json', hit.pkg, vuln, depLoc(hit.pkg.name));
          const names = affectedFunctionNames(vuln);
          if (names.length > 0 && finding.ruleId === 'DEPS-VULN-001') symbols.set(finding.id, names);
          findings.push(finding);
        }
      }
      const noLockCtx = await reachabilityCtx(ctx.cwd, ctx.files, graphFromManifest(manifest), ctx.config.sast.maxFileBytes);
      return withWorkspaceAdvisories(ctx.cwd, manifestRaw, osvOpts, applyReachability(findings, noLockCtx, symbols));
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
    const symbols = new Map<string, readonly string[]>();
    for (const hit of osvHits) {
      for (const vuln of hit.vulns) {
        const finding = isMaliciousAdvisory(vuln)
          ? maliciousFinding(lockFile, hit.pkg, vuln)
          : vulnFinding(lockFile, hit.pkg, vuln, depLoc(hit.pkg.name));
        const names = affectedFunctionNames(vuln);
        if (names.length > 0 && finding.ruleId === 'DEPS-VULN-001') symbols.set(finding.id, names);
        findings.push(finding);
      }
    }
    const reachCtx = await reachabilityCtx(ctx.cwd, ctx.files, graph, ctx.config.sast.maxFileBytes);
    let reached = applyReachability(findings, reachCtx, symbols);
    if (experimentalVex()) {
      reached = attachOverrideProposals(reached, graph, lockFile, manifestRaw);
      reached.push(...scanInstalledPackages(ctx.cwd, packages));
    }
    if (licenseEnabled()) reached.push(...(await scanCopyleftLicenses(ctx.cwd)));
    depsModule.unusedDirect = unusedDirectPlan(reached, reachCtx);
    const direct = new Set([...graph.directProd, ...graph.directDev]);
    const advisories: UpgradeAdvisory[] = [];
    for (const hit of osvHits) {
      if (!direct.has(hit.pkg.name)) continue;
      for (const vuln of hit.vulns) {
        if (isMaliciousAdvisory(vuln)) continue;
        advisories.push({
          name: hit.pkg.name,
          from: hit.pkg.version,
          id: vuln.id,
          fixed: minFixedVersion(vuln.affected ?? []),
        });
      }
    }
    depsModule.upgradePlan = chooseUpgradePlan(advisories);
    if (process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE === '1') {
      const sites = collectImportSites(reachCtx.sources);
      const files = [...reachCtx.sources.keys()].sort();
      reached = reached.map((finding) => {
        const evidence = evidenceForFinding(finding, sites, files, graph.edgesKnown);
        return evidence === undefined ? finding : { ...finding, reachabilityEvidence: evidence };
      });
    }
    reached = await withWorkspaceAdvisories(ctx.cwd, manifestRaw, osvOpts, reached);
    const shapeSources: { file: string; text: string }[] = [];
    for (const rel of ctx.files) {
      if (!/\.[cm]?[jt]sx?$/.test(rel)) continue;
      try {
        shapeSources.push({ file: rel, text: await readFile(join(ctx.cwd, rel), 'utf8') });
      } catch {
        continue;
      }
    }
    reached = [...reached, ...dependencyShapeFindings(manifestRaw, packages, shapeSources)];
    if (capabilitiesEnabled()) {
      reached.push(
        ...capabilityFindings({
          cwd: ctx.cwd,
          lockText: contents,
          cacheDir,
          policy: ctx.config.deps.capabilityPolicy,
        }),
      );
    }
    if (process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY === '1') {
      reached.push(...campaignFindings([...reachCtx.sources.entries()].map(([file, text]) => ({ file, text }))));
      for (const name of [...direct].sort()) {
        const locked = packages.find((pkg) => pkg.name === name)?.version;
        if (locked === undefined) continue;
        const latest = await readPlaceholderLatest(join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`));
        const placeholder = securityPlaceholderFinding(name, locked, latest);
        if (placeholder !== undefined) reached.push(placeholder);
      }
    }
    if (provenanceEnabled()) {
      const provenance = await provenanceFindingsForScan(packages, lockFile, {
        cacheDir,
        offline: ctx.config.deps.offline,
      });
      reached.push(...provenance.findings);
    }
    return reached;
  },
};

function workspacesEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES === '1';
}

function workspacePatterns(manifestRaw: string): string[] {
  try {
    const manifest = JSON.parse(manifestRaw) as { workspaces?: unknown };
    const field = manifest.workspaces;
    if (Array.isArray(field)) return field.filter((item): item is string => typeof item === 'string');
    if (field !== null && typeof field === 'object' && Array.isArray((field as { packages?: unknown }).packages)) {
      return (field as { packages: unknown[] }).packages.filter((item): item is string => typeof item === 'string');
    }
  } catch {
    return [];
  }
  return [];
}

async function expandWorkspace(cwd: string, pattern: string): Promise<string[]> {
  const normalized = pattern.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!normalized.includes('*')) return [normalized];
  const slash = normalized.indexOf('/*');
  if (slash < 0) return [];
  const parent = normalized.slice(0, slash);
  try {
    const entries = await readdir(join(cwd, parent), { withFileTypes: true });
    return entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => `${parent}/${entry.name}`)
      .sort();
  } catch {
    return [];
  }
}

async function workspaceAdvisoryFindings(
  cwd: string,
  manifestRaw: string,
  osvOpts: { cacheDir: string; offline: boolean },
): Promise<Finding[]> {
  const dirs = new Set<string>();
  for (const pattern of workspacePatterns(manifestRaw)) {
    for (const dir of await expandWorkspace(cwd, pattern)) dirs.add(dir);
  }
  const findings: Finding[] = [];
  for (const dir of [...dirs].sort()) {
    if (dir === '' || dir === '.') continue;
    const lockName = LOCKFILE_NAMES.find((name) => existsSync(join(cwd, dir, name)));
    if (lockName === undefined) continue;
    let text: string;
    try {
      text = await readFile(join(cwd, dir, lockName), 'utf8');
    } catch {
      continue;
    }
    const graph = parseLockfileGraph(lockName, text);
    const hits = await queryOsv(graph.packages, osvOpts);
    const file = `${dir}/${lockName}`;
    for (const hit of hits) {
      for (const vuln of hit.vulns) {
        findings.push(
          isMaliciousAdvisory(vuln) ? maliciousFinding(file, hit.pkg, vuln) : vulnFinding(file, hit.pkg, vuln),
        );
      }
    }
  }
  return findings;
}

async function withWorkspaceAdvisories(
  cwd: string,
  manifestRaw: string | undefined,
  osvOpts: { cacheDir: string; offline: boolean },
  findings: Finding[],
): Promise<Finding[]> {
  if (!workspacesEnabled() || manifestRaw === undefined) return findings;
  return [...findings, ...(await workspaceAdvisoryFindings(cwd, manifestRaw, osvOpts))];
}

async function readPlaceholderLatest(file: string): Promise<string | undefined> {
  try {
    const raw = JSON.parse(await readFile(file, 'utf8')) as { latest?: string };
    return typeof raw.latest === 'string' ? raw.latest : undefined;
  } catch {
    return undefined;
  }
}

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
  maxFileBytes: number,
): Promise<{
  productionUsage: Map<string, { imported: boolean; called: boolean }>;
  graph: LockfileGraph;
  sources: Map<string, string>;
}> {
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
  const productionUsage = perf2Enabled()
    ? indexPackageUsageCached(prodSources, callGraphConfigHash(maxFileBytes))
    : indexPackageUsage(prodSources);
  return { productionUsage, graph, sources: prodSources };
}
