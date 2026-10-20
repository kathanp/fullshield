import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../../core/finding.js';

const COPYLEFT = /(?:^|[^\w])(?:AGPL|GPL)(?:-|[^\w]|$)/i;

export function isCopyleftLicense(license: string): boolean {
  return COPYLEFT.test(license);
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

/**
 * Flag direct dependencies whose installed package.json says GPL or AGPL.
 * Missing `node_modules` produces no findings. Does not guess a license.
 */
export async function scanCopyleftLicenses(cwd: string): Promise<Finding[]> {
  const manifest = await readJson(join(cwd, 'package.json'));
  if (typeof manifest !== 'object' || manifest === null) {return [];}
  const names = new Set<string>();
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const block = (manifest as Record<string, unknown>)[field];
    if (typeof block === 'object' && block !== null && !Array.isArray(block)) {
      for (const name of Object.keys(block)) {names.add(name);}
    }
  }
  const findings: Finding[] = [];
  for (const name of names) {
    const pkg = await readJson(join(cwd, 'node_modules', name, 'package.json'));
    if (typeof pkg !== 'object' || pkg === null) {continue;}
    const license = licenseText((pkg as { license?: unknown }).license);
    if (license === undefined || !isCopyleftLicense(license)) {continue;}
    findings.push({
      id: makeFindingId('DEPS-LICENSE-001', 'package.json', `${name}|${license}`),
      ruleId: 'DEPS-LICENSE-001',
      module: 'deps',
      title: `Copyleft dependency ${name}`,
      severity: 'medium',
      confidence: 'high',
      file: 'package.json',
      snippet: `${name} ${license}`,
      message: `${name} is licensed ${license}.`,
      remediation: 'Replace the dependency or get a legal review before shipping it in a commercial product.',
    });
  }
  return findings;
}
