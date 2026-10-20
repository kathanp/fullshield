import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';
import { readCached, writeCached } from './cache.js';
import { detectPackage } from './detect.js';
import { readLockPackages, type LockedCapPackage } from './lock.js';
import type { CapabilityName } from './names.js';
import { policyAction, type CapabilityPolicy } from './policy.js';

const CAPABILITIES_FLAG = 'FULLSHIELD_EXPERIMENTAL_CAPABILITIES';

interface CapabilityHit {
  capability: CapabilityName;
  introducedBy: string;
  policy?: 'deny' | 'warn';
}

interface DirectCapabilityProfile {
  name: string;
  version: string;
  capabilities: CapabilityHit[];
}

interface NewCapability {
  name: string;
  from?: string;
  to: string;
  capability: CapabilityName;
  introducedBy: string;
}

export function capabilitiesEnabled(): boolean {
  return process.env[CAPABILITIES_FLAG] === '1';
}

export function assertCapabilitiesEnabled(command: string): void {
  if (capabilitiesEnabled()) {return;}
  const error = new Error(`${command} requires ${CAPABILITIES_FLAG}=1`);
  throw error;
}

function installedDir(cwd: string, row: LockedCapPackage): string | undefined {
  const candidates = [join(cwd, row.rel), join(cwd, 'node_modules', row.name)];
  return candidates.find((dir) => existsSync(dir));
}

function packageCaps(cwd: string, row: LockedCapPackage, cacheDir: string): CapabilityName[] {
  if (row.integrity !== undefined) {
    const cached = readCached(cacheDir, row.integrity);
    if (cached !== undefined) {return cached;}
  }
  const dir = installedDir(cwd, row);
  if (dir === undefined) {return [];}
  const caps = detectPackage(dir);
  if (row.integrity !== undefined) {writeCached(cacheDir, row.integrity, caps);}
  return caps;
}

function closure(name: string, rows: Map<string, LockedCapPackage>): string[] {
  const seen = new Set<string>();
  const stack = [name];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined || seen.has(current)) {continue;}
    seen.add(current);
    for (const dep of rows.get(current)?.deps ?? []) {stack.push(dep);}
  }
  return [...seen].sort();
}

function hitsFor(
  direct: LockedCapPackage,
  rows: Map<string, LockedCapPackage>,
  caps: Map<string, CapabilityName[]>,
  policy: CapabilityPolicy | undefined,
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  for (const name of closure(direct.name, rows)) {
    const row = rows.get(name);
    if (row === undefined) {continue;}
    const introducedBy = `${row.name}@${row.version}`;
    for (const capability of caps.get(name) ?? []) {
      const action = policyAction(policy, capability, [direct.name, row.name]);
      const hit: CapabilityHit = { capability, introducedBy };
      if (action !== undefined) {hit.policy = action;}
      hits.push(hit);
    }
  }
  hits.sort((a, b) => a.capability.localeCompare(b.capability) || a.introducedBy.localeCompare(b.introducedBy));
  return hits;
}

function profilesFromLock(
  cwd: string,
  lockText: string,
  cacheDir: string,
  policy?: CapabilityPolicy,
): DirectCapabilityProfile[] {
  const parsed = readLockPackages(lockText);
  if (parsed === undefined) {return [];}
  const rows = new Map(parsed.packages.map((pkg) => [pkg.name, pkg]));
  const caps = new Map(parsed.packages.map((pkg) => [pkg.name, packageCaps(cwd, pkg, cacheDir)]));
  const profiles: DirectCapabilityProfile[] = [];
  for (const name of parsed.direct) {
    const row = rows.get(name);
    if (row === undefined) {continue;}
    profiles.push({ name: row.name, version: row.version, capabilities: hitsFor(row, rows, caps, policy) });
  }
  return profiles;
}

export function profileProject(cwd: string, cacheDir: string, policy?: CapabilityPolicy): DirectCapabilityProfile[] {
  try {
    return profilesFromLock(cwd, readFileSync(join(cwd, 'package-lock.json'), 'utf8'), cacheDir, policy);
  } catch {
    return [];
  }
}

export function formatCapabilityReport(rows: readonly DirectCapabilityProfile[]): string {
  const lines: string[] = [];
  for (const row of rows) {
    lines.push(`${row.name}@${row.version}`);
    if (row.capabilities.length === 0) {
      lines.push('  (none)');
      continue;
    }
    for (const hit of row.capabilities) {
      const mark = hit.policy === 'warn' ? ' warn' : '';
      lines.push(`  ${hit.capability} via ${hit.introducedBy}${mark}`);
    }
  }
  return lines.join('\n');
}

function capFinding(row: DirectCapabilityProfile, hit: CapabilityHit): Finding {
  const message = `${row.name}@${row.version} capability ${hit.capability} denied by deps.capabilityPolicy (via ${hit.introducedBy})`;
  const at = hit.introducedBy.lastIndexOf('@');
  const introducer = at > 0 ? hit.introducedBy.slice(0, at) : hit.introducedBy;
  const file = `node_modules/${introducer}/package.json`;
  return {
    id: makeFindingId('SUPPLY-CAP-001', file, message),
    ruleId: 'SUPPLY-CAP-001',
    module: 'deps',
    title: 'Dependency capability denied by policy',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-829',
    file,
    snippet: hit.introducedBy,
    message,
    remediation: 'Remove the package, or change deps.capabilityPolicy if this capability is expected.',
  };
}

export function capabilityFindings(input: {
  cwd: string;
  lockText: string;
  cacheDir: string;
  policy: CapabilityPolicy | undefined;
}): Finding[] {
  if (!capabilitiesEnabled()) {return [];}
  const profiles = profilesFromLock(input.cwd, input.lockText, input.cacheDir, input.policy);
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const row of profiles) {
    for (const hit of row.capabilities) {
      if (hit.policy !== 'deny') {continue;}
      const key = `${hit.capability}\0${hit.introducedBy}`;
      if (seen.has(key)) {continue;}
      seen.add(key);
      findings.push(capFinding(row, hit));
    }
  }
  return findings;
}

export function introducedCapabilities(input: {
  beforeText: string;
  afterText: string;
  cwd: string;
  cacheDir: string;
}): NewCapability[] {
  const before = readLockPackages(input.beforeText);
  const after = readLockPackages(input.afterText);
  if (before === undefined || after === undefined) {return [];}
  const old = new Map(before.packages.map((pkg) => [pkg.name, pkg]));
  const out: NewCapability[] = [];
  for (const pkg of after.packages) {
    const prev = old.get(pkg.name);
    if (prev !== undefined && prev.version === pkg.version) {continue;}
    const prior = prev === undefined ? [] : readCached(input.cacheDir, prev.integrity);
    if (prior === undefined) {continue;}
    const known = new Set(prior);
    for (const capability of packageCaps(input.cwd, pkg, input.cacheDir)) {
      if (known.has(capability)) {continue;}
      out.push({
        name: pkg.name,
        from: prev?.version,
        to: pkg.version,
        capability,
        introducedBy: `${pkg.name}@${pkg.version}`,
      });
    }
  }
  out.sort((a, b) => a.name.localeCompare(b.name) || a.capability.localeCompare(b.capability));
  return out;
}
