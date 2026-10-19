import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';

export const CAPABILITY_NAMES = [
  'child_process',
  'net',
  'fs-write',
  'process.env',
  'eval',
  'native',
  'dynamic-require',
  'install-script',
  'obfuscation',
] as const;

export type CapabilityName = (typeof CAPABILITY_NAMES)[number];

export interface CapabilityProfile {
  name: string;
  version: string;
  capabilities: CapabilityName[];
  introducedBy: string;
}

const SIGNAL: Array<{ name: CapabilityName; test: (source: string, scripts: string) => boolean }> = [
  { name: 'child_process', test: (source) => /require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]/.test(source) },
  { name: 'net', test: (source) => /require\(\s*['"](?:net|http|https|dgram)['"]\s*\)|\bfetch\s*\(/.test(source) },
  { name: 'fs-write', test: (source) => /\bfs\.(?:writeFile|appendFile|rm|unlink|mkdir)\b/.test(source) },
  { name: 'process.env', test: (source) => /process\.env\b/.test(source) },
  { name: 'eval', test: (source) => /\beval\s*\(|new\s+Function\s*\(|\bvm\./.test(source) },
  { name: 'native', test: (source) => /binding\.gyp|\.node\b/.test(source) },
  { name: 'dynamic-require', test: (source) => /require\(\s*[^'"]/.test(source) },
  { name: 'install-script', test: (_source, scripts) => /"(?:preinstall|install|postinstall)"\s*:/.test(scripts) },
  { name: 'obfuscation', test: (source) => /\\x[0-9a-fA-F]{2}/.test(source) || /[A-Za-z0-9+/]{200,}={0,2}/.test(source) },
];

async function readTree(dir: string): Promise<string> {
  let text = '';
  let entries: string[] = [];
  try {
    entries = await readdir(dir);
  } catch {
    return text;
  }
  for (const name of entries) {
    if (name === 'node_modules' || name === '.git') continue;
    const path = join(dir, name);
    if (name.endsWith('.js') || name.endsWith('.cjs') || name.endsWith('.mjs') || name === 'package.json') {
      try {
        text += await readFile(path, 'utf8');
      } catch {
        continue;
      }
    }
  }
  return text;
}

export async function profilePackage(root: string, name: string): Promise<CapabilityProfile | undefined> {
  const dir = join(root, 'node_modules', name);
  let manifest = '';
  try {
    manifest = await readFile(join(dir, 'package.json'), 'utf8');
  } catch {
    return undefined;
  }
  const parsed = JSON.parse(manifest) as { version?: string; scripts?: Record<string, string> };
  const source = await readTree(dir);
  const scripts = JSON.stringify(parsed.scripts ?? {});
  const capabilities = SIGNAL.filter((item) => item.test(source + manifest, scripts)).map((item) => item.name);
  return {
    name,
    version: parsed.version ?? '0.0.0',
    capabilities,
    introducedBy: name,
  };
}

export function capabilityFinding(profile: CapabilityProfile, denied: readonly string[]): Finding | undefined {
  const hit = profile.capabilities.find((name) => denied.includes(name));
  if (hit === undefined) return undefined;
  return {
    id: makeFindingId('SUPPLY-CAP-001', 'package.json', `${profile.name}:${hit}`),
    ruleId: 'SUPPLY-CAP-001',
    module: 'deps',
    title: 'Dependency capability denied by policy',
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-829',
    file: 'package.json',
    snippet: `${profile.name} ${hit}`,
    message: `${profile.name}@${profile.version} can ${hit}. The capability policy denies it.`,
    remediation: 'Remove the package or change deps.capabilityPolicy. This is not a malware verdict.',
  };
}
