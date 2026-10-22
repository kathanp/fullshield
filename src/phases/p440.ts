/**
 * Phase 440. Per-package monorepo reports.
 * Off unless FULLSHIELD_EXPERIMENTAL_MONOREPORT=1.
 * Flag off: the single report string is returned unchanged.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MONOREPORT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface WorkspacePackage {
  name: string;
  dir: string;
  dependencies: readonly string[];
}

export interface MonoFinding {
  fingerprint: string;
  file: string;
  ruleId: string;
  line: number;
  severity: string;
}

export interface PackageReport {
  name: string;
  findings: Array<MonoFinding & { path: string }>;
  inherited: string[];
}

export interface MonoReports {
  single: string | null;
  packages: Record<string, PackageReport>;
  rollupCount: number;
}

function owner(file: string, packages: readonly WorkspacePackage[]): WorkspacePackage | null {
  const sorted = [...packages].sort((left, right) => right.dir.length - left.dir.length);
  return sorted.find((pkg) => file === pkg.dir || file.startsWith(`${pkg.dir}/`)) ?? null;
}

function relativePath(file: string, dir: string): string {
  if (file === dir) {
    return file;
  }
  if (file.startsWith(`${dir}/`)) {
    return file.slice(dir.length + 1);
  }
  return file;
}

export function splitReports(baseline: string, findings: readonly MonoFinding[], packages: readonly WorkspacePackage[]): MonoReports {
  if (!enabled()) {
    return { single: baseline, packages: {}, rollupCount: 0 };
  }
  const packagesOut: Record<string, PackageReport> = {};
  const ensure = (name: string): PackageReport => {
    const existing = packagesOut[name];
    if (existing !== undefined) {
      return existing;
    }
    const created: PackageReport = { name, findings: [], inherited: [] };
    packagesOut[name] = created;
    return created;
  };
  const rollup = new Set<string>();
  for (const finding of findings) {
    const pkg = owner(finding.file, packages);
    const name = pkg === null ? '_root' : pkg.name;
    const dir = pkg === null ? '' : pkg.dir;
    const path = pkg === null ? finding.file : relativePath(finding.file, dir);
    ensure(name).findings.push({ ...finding, path });
    rollup.add(finding.fingerprint);
  }
  for (const pkg of packages) {
    for (const dep of pkg.dependencies) {
      const shared = packagesOut[dep];
      if (shared !== undefined && shared.findings.length > 0) {
        ensure(pkg.name).inherited.push(dep);
      }
    }
  }
  return { single: null, packages: packagesOut, rollupCount: rollup.size };
}
