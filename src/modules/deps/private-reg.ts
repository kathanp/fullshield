import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, sortFindings, type Finding, type Severity } from '../../core/finding.js';

const PRIVATE_REG_FLAG = 'FULLSHIELD_EXPERIMENTAL_PRIVATE_REG';
export const ORG_ADVISORY_MAX_BYTES = 1000000;

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

const SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);

export interface OrgAdvisory {
  name: string;
  version: string;
  id: string;
  severity: Severity;
  summary: string;
}

export interface InstalledDep {
  name: string;
  version: string;
}

export function privateRegistryContactsNetwork(): boolean {
  return false;
}

export function orgAdvisoryWithinCap(byteLength: number): boolean {
  return byteLength <= ORG_ADVISORY_MAX_BYTES;
}

export function parsePrivateRegistry(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(`deps.registry must be https with no userinfo (${PRIVATE_REG_FLAG})`);
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hostname.length === 0) {
    fail(`deps.registry must be https with no userinfo (${PRIVATE_REG_FLAG})`);
  }
  return url.hostname;
}

function advisoryFrom(row: unknown): OrgAdvisory {
  if (typeof row !== 'object' || row === null) {
    fail(`org advisory row is invalid (${PRIVATE_REG_FLAG})`);
  }
  const item = row as Record<string, unknown>;
  const severity = item.severity;
  if (typeof item.name !== 'string' || typeof item.version !== 'string' || typeof item.id !== 'string') {
    fail(`org advisory row is invalid (${PRIVATE_REG_FLAG})`);
  }
  if (typeof item.summary !== 'string' || typeof severity !== 'string' || !SEVERITIES.has(severity as Severity)) {
    fail(`org advisory row is invalid (${PRIVATE_REG_FLAG})`);
  }
  return {
    name: item.name,
    version: item.version,
    id: item.id,
    severity: severity as Severity,
    summary: item.summary,
  };
}

export function parseOrgAdvisoryDocument(text: string): OrgAdvisory[] {
  if (!orgAdvisoryWithinCap(Buffer.byteLength(text))) {
    fail(`org advisory cache exceeds ${ORG_ADVISORY_MAX_BYTES} bytes (${PRIVATE_REG_FLAG})`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    fail(`org advisory cache is not JSON (${PRIVATE_REG_FLAG})`);
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    fail(`org advisory cache must be an object (${PRIVATE_REG_FLAG})`);
  }
  const advisories = (raw as { advisories?: unknown }).advisories;
  if (!Array.isArray(advisories)) {
    fail(`org advisory cache must list advisories (${PRIVATE_REG_FLAG})`);
  }
  return advisories.map((row) => advisoryFrom(row));
}

export function matchOrgAdvisories(installed: readonly InstalledDep[], advisories: readonly OrgAdvisory[]): Finding[] {
  const findings: Finding[] = [];
  for (const dep of installed) {
    for (const advisory of advisories) {
      if (advisory.name !== dep.name || advisory.version !== dep.version) {continue;}
      findings.push({
        id: makeFindingId('DEPS-ORG-ADV-001', 'package.json', `${dep.name}@${dep.version}|${advisory.id}`),
        ruleId: 'DEPS-ORG-ADV-001',
        module: 'deps',
        title: `Org advisory ${advisory.id}`,
        severity: advisory.severity,
        confidence: 'high',
        file: 'package.json',
        snippet: `${dep.name}@${dep.version}`,
        message: `${dep.name}@${dep.version} matches ${advisory.id} from the local org cache, not from a network feed. ${advisory.summary}`,
        remediation: 'Bump or remove the package using the package manager. FullShield did not contact the private registry.',
        references: [advisory.id],
      });
    }
  }
  return sortFindings(findings);
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

export async function scanOrgAdvisories(cwd: string, cacheDir: string): Promise<Finding[]> {
  const file = join(cacheDir, 'org-advisories.json');
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    return [];
  }
  const manifest = await readJson(join(cwd, 'package.json'));
  if (typeof manifest !== 'object' || manifest === null) {return [];}
  const direct = (manifest as { dependencies?: unknown }).dependencies;
  if (typeof direct !== 'object' || direct === null || Array.isArray(direct)) {return [];}
  const installed: InstalledDep[] = [];
  for (const name of Object.keys(direct).sort()) {
    const pkg = await readJson(join(cwd, 'node_modules', name, 'package.json'));
    if (typeof pkg !== 'object' || pkg === null) {continue;}
    const version = (pkg as { version?: unknown }).version;
    if (typeof version !== 'string') {continue;}
    installed.push({ name, version });
  }
  return matchOrgAdvisories(installed, parseOrgAdvisoryDocument(text));
}
