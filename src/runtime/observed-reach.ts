import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, sep } from 'node:path';

import type { Finding } from '../core/finding.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH';

export function observedReachEnabled(): boolean {
  return process.env[FLAG] === '1';
}

/** Package name and export subpath from a loaded `file:` URL under `node_modules`. */
export function packageFromFileUrl(url: string): { name: string; exportName: string } | undefined {
  if (!url.startsWith('file:')) return undefined;
  let pathname: string;
  try {
    pathname = fileURLToPath(url);
  } catch {
    return undefined;
  }
  const marker = `${sep}node_modules${sep}`;
  const at = pathname.lastIndexOf(marker);
  if (at < 0) return undefined;
  const parts = pathname.slice(at + marker.length).split(sep).filter((part) => part.length > 0);
  if (parts.length === 0) return undefined;
  let name: string;
  let rest: string[];
  if (parts[0]?.startsWith('@')) {
    if (parts.length < 2 || parts[1] === undefined) return undefined;
    name = `${parts[0]}/${parts[1]}`;
    rest = parts.slice(2);
  } else {
    name = parts[0] ?? '';
    rest = parts.slice(1);
  }
  if (name.length === 0) return undefined;
  return { name, exportName: exportNameOf(rest) };
}

function exportNameOf(parts: string[]): string {
  if (parts.length === 0) return '.';
  const copy = [...parts];
  const last = copy.length - 1;
  copy[last] = copy[last]!.replace(/\.(?:[cm]?js|node|json)$/, '');
  if (copy[last] === 'index') copy.pop();
  if (copy.length === 0) return '.';
  return copy.join('/');
}

/** Merge one loaded export into `.fullshield/observed-reach.json`. Never throws and never uses the network. */
export async function recordLoaded(cwd: string, name: string, exportName: string): Promise<void> {
  if (!observedReachEnabled()) return;
  try {
    const dir = join(cwd, '.fullshield');
    const file = join(dir, 'observed-reach.json');
    await mkdir(dir, { recursive: true });
    const packages = await readPackages(file);
    const names = new Set(packages[name] ?? []);
    names.add(exportName);
    packages[name] = [...names].sort();
    const ordered: Record<string, string[]> = {};
    for (const key of Object.keys(packages).sort()) ordered[key] = [...(packages[key] ?? [])].sort();
    await writeFile(file, `${JSON.stringify({ packages: ordered }, null, 2)}\n`);
  } catch {
    // Fail open. The app keeps running.
  }
}

async function readPackages(file: string): Promise<Record<string, string[]>> {
  try {
    const raw = JSON.parse(await readFile(file, 'utf8')) as { packages?: unknown };
    if (raw.packages === null || typeof raw.packages !== 'object' || Array.isArray(raw.packages)) return {};
    const packages: Record<string, string[]> = {};
    for (const [name, value] of Object.entries(raw.packages)) {
      if (!Array.isArray(value)) continue;
      packages[name] = value.filter((item): item is string => typeof item === 'string');
    }
    return packages;
  } catch {
    return {};
  }
}

const REACHED = new Set(['reachable', 'symbol-reachable', 'reachable-via-dependency']);
const CONFIRMABLE = new Set(['not-imported', 'imported-not-called', 'symbol-not-called', 'reachability-unknown']);

/** Confirm a runtime-loaded package, or record a downgrade. A bad file leaves findings unchanged. */
export async function applyObservedReach(cwd: string, findings: Finding[]): Promise<Finding[]> {
  if (!observedReachEnabled()) return findings;
  let packages: Record<string, string[]>;
  try {
    const raw = JSON.parse(await readFile(join(cwd, '.fullshield', 'observed-reach.json'), 'utf8')) as {
      packages?: unknown;
    };
    if (raw.packages === null || typeof raw.packages !== 'object' || Array.isArray(raw.packages)) return findings;
    packages = raw.packages as Record<string, string[]>;
  } catch {
    return findings;
  }
  return findings.map((finding) => note(finding, packages));
}

function note(finding: Finding, packages: Record<string, string[]>): Finding {
  if (finding.module !== 'deps') return finding;
  const name = packageName(finding.snippet);
  if (name === undefined) return finding;
  if (Object.prototype.hasOwnProperty.call(packages, name)) {
    const confirmed = CONFIRMABLE.has(finding.reachability ?? '')
      ? { ...finding, reachability: 'reachable' as const }
      : finding;
    return { ...confirmed, observedReach: 'confirmed' };
  }
  if (finding.ruleId === 'DEPS-MALICIOUS-001') return finding;
  if (!REACHED.has(finding.reachability ?? '')) return finding;
  return { ...finding, observedReach: 'downgraded' };
}

function packageName(snippet: string | undefined): string | undefined {
  if (snippet === undefined || snippet.length === 0) return undefined;
  if (snippet.startsWith('@')) {
    const second = snippet.indexOf('@', 1);
    return second === -1 ? snippet : snippet.slice(0, second);
  }
  const at = snippet.indexOf('@');
  return at <= 0 ? snippet : snippet.slice(0, at);
}
