/**
 * Phase 379. Offline OSV file.
 * FULLSHIELD_EXPERIMENTAL_OSVFILE=1 is required when `--osv-file` is set.
 * Ids are used as written. This module does not open a socket.
 */
import { FsError } from './p378.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_OSVFILE';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface LockedPackage {
  name: string;
  version: string;
}

export interface FileAdvisoryFinding {
  ruleId: 'DEPS-VULN-001';
  advisoryId: string;
  packageName: string;
  version: string;
}

export interface OsvFileReport {
  advisorySource: 'file';
  file: string;
  current: false;
  findings: FileAdvisoryFinding[];
}

interface Affected {
  package?: { name?: string; ecosystem?: string };
  versions?: string[];
}

interface Advisory {
  id?: string;
  affected?: Affected[];
}

function asAdvisories(parsed: unknown): Advisory[] {
  if (Array.isArray(parsed)) {
    return parsed as Advisory[];
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new FsError('OSV file is malformed');
  }
  const record = parsed as { vulns?: unknown; results?: unknown };
  if (Array.isArray(record.vulns)) {
    return record.vulns as Advisory[];
  }
  if (Array.isArray(record.results)) {
    const advisories: Advisory[] = [];
    for (const result of record.results) {
      if (typeof result !== 'object' || result === null || !Array.isArray((result as { vulns?: unknown }).vulns)) {
        throw new FsError('OSV file is malformed');
      }
      advisories.push(...((result as { vulns: Advisory[] }).vulns));
    }
    return advisories;
  }
  throw new FsError('OSV file is malformed');
}

function readAdvisories(text: string): Advisory[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new FsError('OSV file is malformed');
  }
  try {
    return asAdvisories(parsed);
  } catch (error) {
    if (error instanceof FsError) {
      throw error;
    }
    throw new FsError('OSV file is malformed');
  }
}

function requireId(advisory: Advisory): string {
  if (typeof advisory.id !== 'string' || advisory.id === '') {
    throw new FsError('OSV file is malformed');
  }
  return advisory.id;
}

function matchLocked(name: string, versions: readonly string[], locked: readonly LockedPackage[], advisoryId: string, findings: FileAdvisoryFinding[]): void {
  for (const lockedPackage of locked) {
    if (lockedPackage.name === name && versions.includes(lockedPackage.version)) {
      findings.push({ ruleId: 'DEPS-VULN-001', advisoryId, packageName: name, version: lockedPackage.version });
    }
  }
}

function matchAdvisory(advisory: Advisory, locked: readonly LockedPackage[], findings: FileAdvisoryFinding[]): void {
  const advisoryId = requireId(advisory);
  for (const item of advisory.affected ?? []) {
    const name = item.package?.name;
    if (typeof name !== 'string') {
      continue;
    }
    matchLocked(name, item.versions ?? [], locked, advisoryId, findings);
  }
}

export function advisoriesFromOsvFile(filePath: string, text: string, locked: readonly LockedPackage[]): OsvFileReport {
  if (!enabled()) {
    throw new FsError('OSV file option requires FULLSHIELD_EXPERIMENTAL_OSVFILE=1');
  }
  const findings: FileAdvisoryFinding[] = [];
  for (const advisory of readAdvisories(text)) {
    matchAdvisory(advisory, locked, findings);
  }
  return { advisorySource: 'file', file: filePath, current: false, findings };
}
