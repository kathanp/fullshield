import { builtinModules } from 'node:module';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { rangeSatisfies } from './semver.js';

const BUILTINS = new Set(builtinModules.flatMap((name) => [name, name.replace(/^node:/, '')]));

export function dependencyShapeFindings(
  manifestRaw: string | undefined,
  locked: readonly { name: string; version: string }[],
  sources: readonly { file: string; text: string }[],
): Finding[] {
  const declared = declaredRanges(manifestRaw);
  const findings: Finding[] = [];
  const seenPhantom = new Set<string>();
  for (const source of sources) {
    for (const spec of importedSpecs(source.text)) {
      const name = packageName(spec);
      if (name === undefined || declared.has(name)) continue;
      const key = `${name}\t${source.file}`;
      if (seenPhantom.has(key)) continue;
      seenPhantom.add(key);
      findings.push({
        id: makeFindingId('DEPS-PHANTOM-001', source.file, name),
        ruleId: 'DEPS-PHANTOM-001',
        module: 'deps',
        title: `Imported package ${name} is not declared`,
        severity: 'medium',
        confidence: 'high',
        file: source.file,
        snippet: name,
        message: `${source.file} imports ${name}, which is not in dependencies, devDependencies, optionalDependencies, or peerDependencies.`,
        remediation: `Add ${name} to package.json or remove the import.`,
      });
    }
  }
  const lockedVersion = new Map<string, string>();
  for (const pkg of locked) if (!lockedVersion.has(pkg.name)) lockedVersion.set(pkg.name, pkg.version);
  for (const [name, range] of [...declared.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const version = lockedVersion.get(name);
    if (version === undefined || range === undefined) continue;
    const ok = rangeSatisfies(range, version);
    if (ok !== false) continue;
    findings.push({
      id: makeFindingId('DEPS-LOCKMISMATCH-001', 'package.json', `${name}@${version}`),
      ruleId: 'DEPS-LOCKMISMATCH-001',
      module: 'deps',
      title: `Locked ${name}@${version} does not satisfy ${range}`,
      severity: 'medium',
      confidence: 'high',
      file: 'package.json',
      snippet: `${name}@${version}`,
      message: `package.json asks for ${name} ${range}, and the lockfile has ${version}.`,
      remediation: `Regenerate the lockfile so ${name} satisfies ${range}.`,
    });
  }
  return findings;
}

function declaredRanges(manifestRaw: string | undefined): Map<string, string | undefined> {
  const declared = new Map<string, string | undefined>();
  if (manifestRaw === undefined) return declared;
  try {
    const manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const block = manifest[field];
      if (block === null || typeof block !== 'object' || Array.isArray(block)) continue;
      for (const [name, range] of Object.entries(block)) {
        declared.set(name, typeof range === 'string' ? range : undefined);
      }
    }
  } catch {
    return declared;
  }
  return declared;
}

function importedSpecs(source: string): string[] {
  const specs: string[] = [];
  const pattern = /(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"])/g;
  for (const match of source.matchAll(pattern)) {
    const spec = match[1] ?? match[2];
    if (spec !== undefined) specs.push(spec);
  }
  return specs;
}

function packageName(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return undefined;
  if (BUILTINS.has(spec)) return undefined;
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : undefined;
  }
  const name = spec.split('/')[0];
  if (name === undefined || name.length === 0 || BUILTINS.has(name)) return undefined;
  return name;
}
