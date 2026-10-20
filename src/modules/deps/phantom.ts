import { builtinModules } from 'node:module';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { rangeSatisfies } from './semver.js';

const BUILTINS = new Set(builtinModules.flatMap((name) => [name, name.replace(/^node:/, '')]));

const DEV_PATH_DIRS = new Set(['test', 'tests', '__tests__', 'scripts', 'seeds']);

export function dependencyShapeFindings(
  manifestRaw: string | undefined,
  locked: readonly { name: string; version: string }[],
  sources: readonly { file: string; text: string }[],
): Finding[] {
  const declared = declaredRanges(manifestRaw);
  const devDeclared = devDependencyNames(manifestRaw);
  const findings: Finding[] = [];
  const seenPhantom = new Set<string>();
  for (const source of sources) {
    for (const imported of importedSpecs(source.text)) {
      const name = packageName(imported.spec);
      if (name === undefined || declared.has(name)) {continue;}
      if (devSatisfiedPath(source.file) && devDeclared.has(name)) {continue;}
      const key = `${name}\t${source.file}\t${imported.line}`;
      if (seenPhantom.has(key)) {continue;}
      seenPhantom.add(key);
      findings.push({
        id: makeFindingId('DEPS-PHANTOM-001', source.file, `${name}@${imported.line}`),
        ruleId: 'DEPS-PHANTOM-001',
        module: 'deps',
        title: `Imported package ${name} is not declared`,
        severity: devSatisfiedPath(source.file) ? 'low' : 'medium',
        confidence: 'high',
        file: source.file,
        line: imported.line,
        snippet: name,
        message: `${source.file} imports ${name}, which is not in dependencies, devDependencies, optionalDependencies, or peerDependencies.`,
        remediation: `Add ${name} to package.json or remove the import.`,
      });
    }
  }
  const lockedVersion = new Map<string, string>();
  for (const pkg of locked) {if (!lockedVersion.has(pkg.name)) {lockedVersion.set(pkg.name, pkg.version);}}
  const seenMismatch = new Set<string>();
  for (const [name, range] of [...declared.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const version = lockedVersion.get(name);
    if (version === undefined || range === undefined) {continue;}
    const ok = rangeSatisfies(range, version);
    if (ok !== false) {continue;}
    if (seenMismatch.has(name)) {continue;}
    seenMismatch.add(name);
    const line = manifestLine(manifestRaw, name);
    if (line === undefined) {continue;}
    findings.push({
      id: makeFindingId('DEPS-LOCKMISMATCH-001', 'package.json', `${name}@${version}@${line}`),
      ruleId: 'DEPS-LOCKMISMATCH-001',
      module: 'deps',
      title: `Locked ${name}@${version} does not satisfy ${range}`,
      severity: 'medium',
      confidence: 'high',
      file: 'package.json',
      line,
      snippet: `${name}@${version}`,
      message: `package.json asks for ${name} ${range}, and the lockfile has ${version}.`,
      remediation: `Regenerate the lockfile so ${name} satisfies ${range}.`,
    });
  }
  return findings;
}

function devSatisfiedPath(file: string): boolean {
  const parts = file.split('\\').join('/').split('/');
  if (parts.slice(0, -1).some((part) => DEV_PATH_DIRS.has(part))) {return true;}
  return /\.(test|spec)\./.test(parts[parts.length - 1] ?? '');
}

function manifestLine(manifestRaw: string | undefined, name: string): number | undefined {
  if (manifestRaw === undefined) {return undefined;}
  const needle = `"${name}"`;
  const index = manifestRaw.split(/\r?\n/).findIndex((row) => row.includes(needle));
  return index >= 0 ? index + 1 : undefined;
}

function declaredRanges(manifestRaw: string | undefined): Map<string, string | undefined> {
  const declared = new Map<string, string | undefined>();
  if (manifestRaw === undefined) {return declared;}
  try {
    const manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const block = manifest[field];
      if (block === null || typeof block !== 'object' || Array.isArray(block)) {continue;}
      for (const [name, range] of Object.entries(block)) {
        declared.set(name, typeof range === 'string' ? range : undefined);
      }
    }
  } catch {
    return declared;
  }
  return declared;
}

function devDependencyNames(manifestRaw: string | undefined): Set<string> {
  const names = new Set<string>();
  if (manifestRaw === undefined) {return names;}
  try {
    const manifest = JSON.parse(manifestRaw) as { devDependencies?: unknown };
    const block = manifest.devDependencies;
    if (block === null || typeof block !== 'object' || Array.isArray(block)) {return names;}
    for (const name of Object.keys(block)) {names.add(name);}
  } catch {
    return names;
  }
  return names;
}

function importedSpecs(source: string): Array<{ spec: string; line: number }> {
  const specs: Array<{ spec: string; line: number }> = [];
  const pattern = /(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"])/g;
  source.split(/\r?\n/).forEach((row, index) => {
    for (const match of row.matchAll(pattern)) {
      const spec = match[1] ?? match[2];
      if (spec !== undefined) {specs.push({ spec, line: index + 1 });}
    }
  });
  return specs;
}

function packageName(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {return undefined;}
  if (BUILTINS.has(spec)) {return undefined;}
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : undefined;
  }
  const name = spec.split('/')[0];
  if (name === undefined || name.length === 0 || BUILTINS.has(name)) {return undefined;}
  return name;
}
