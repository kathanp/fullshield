import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, sortFindings, type Finding } from '../../core/finding.js';

const MANIFEST_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

function norm(value: string): string {
  return value.trim().toLowerCase();
}

function licenseText(value: unknown): string | undefined {
  if (typeof value === 'string') {return value;}
  if (typeof value === 'object' && value !== null && 'type' in value) {
    const type = (value as { type?: unknown }).type;
    if (typeof type === 'string') {return type;}
  }
  return undefined;
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

function listed(license: string, list: readonly string[]): boolean {
  const key = norm(license);
  return list.some((entry) => norm(entry) === key);
}

function manifestNames(manifest: unknown): string[] {
  if (typeof manifest !== 'object' || manifest === null) {return [];}
  const names = new Set<string>();
  for (const field of MANIFEST_FIELDS) {
    const block = (manifest as Record<string, unknown>)[field];
    if (typeof block !== 'object' || block === null || Array.isArray(block)) {continue;}
    for (const name of Object.keys(block)) {names.add(name);}
  }
  return [...names].sort();
}

function policyHit(license: string, deny: readonly string[], allow: readonly string[]): boolean {
  if (listed(license, allow)) {return false;}
  if (listed(license, deny)) {return true;}
  return allow.length > 0;
}

function licenseFinding(name: string, license: string): Finding {
  return {
    id: makeFindingId('DEPS-LICENSE-002', 'package.json', `${name}|${license}`),
    ruleId: 'DEPS-LICENSE-002',
    module: 'deps',
    title: `License policy: ${name}`,
    severity: 'medium',
    confidence: 'high',
    file: 'package.json',
    snippet: `${name} ${license}`,
    message: `${name} is licensed ${license}. This is a license policy, not a vulnerability.`,
    remediation: 'Change the dependency or update deps.licenseDeny / deps.licenseAllow.',
  };
}

/**
 * Direct-dependency license policy. Missing installs and missing license strings stay silent.
 * The finding is a policy hit, not a vulnerability.
 */
export async function scanLicensePolicy(
  cwd: string,
  lists: { deny?: readonly string[]; allow?: readonly string[] },
): Promise<Finding[]> {
  const deny = lists.deny ?? [];
  const allow = lists.allow ?? [];
  if (deny.length === 0 && allow.length === 0) {return [];}
  const names = manifestNames(await readJson(join(cwd, 'package.json')));
  const findings: Finding[] = [];
  for (const name of names) {
    const pkg = await readJson(join(cwd, 'node_modules', name, 'package.json'));
    if (typeof pkg !== 'object' || pkg === null) {continue;}
    const license = licenseText((pkg as { license?: unknown }).license);
    if (license === undefined || !policyHit(license, deny, allow)) {continue;}
    findings.push(licenseFinding(name, license));
  }
  return sortFindings(findings);
}
