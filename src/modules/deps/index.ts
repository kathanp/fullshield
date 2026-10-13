import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { parseLockfile, type LockedPackage } from './lockfile.js';
import { queryOsv, type OsvVuln } from './osv.js';
import { minFixedVersion, osvSeverity, sameMajor } from './semver.js';
import { findTyposquats, type TyposquatHit } from './typosquat.js';

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

function defaultCacheDir(): string {
  return join(homedir(), '.cache', 'fullshield');
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
    if (lockFile === undefined) return [];

    let contents: string;
    try {
      contents = await readFile(join(ctx.cwd, lockFile), 'utf8');
    } catch {
      return [];
    }

    const packages = parseLockfile(lockFile, contents);
    const findings: Finding[] = [];

    for (const hit of findTyposquats(packages)) {
      findings.push(typosquatFinding(lockFile, hit));
    }
    for (const pkg of packages) {
      if (pkg.deprecated !== undefined) {
        findings.push(deprecatedFinding(lockFile, pkg));
      }
    }

    const cacheDir =
      ctx.config.deps.cacheDir !== undefined
        ? resolve(ctx.cwd, ctx.config.deps.cacheDir)
        : defaultCacheDir();

    const osvHits = await queryOsv(packages, {
      cacheDir,
      offline: ctx.config.deps.offline,
    });
    for (const hit of osvHits) {
      for (const vuln of hit.vulns) {
        findings.push(vulnFinding(lockFile, hit.pkg, vuln));
      }
    }
    return findings;
  },
};
