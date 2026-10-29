import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { registryCachePath } from '../../provenance/index.js';
import { rankBumpsFromScan, type RankedBump } from './bump-pr.js';

const SCRIPT_HOOKS = ['preinstall', 'install', 'postinstall'] as const;

export interface InstallScriptReport {
  name: string;
  scripts: { hook: string; source: string }[];
}

export interface ProvenanceBlock {
  name: string;
  to: string;
  reason: 'absent';
}

export interface BumpPlan {
  bumps: RankedBump[];
  skippedNotImported: number;
  installScripts: InstallScriptReport[];
  provenanceBlocked: ProvenanceBlock[];
}

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function defaultCacheDir(): string {
  return join(homedir(), '.cache', 'fullshield');
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function parseScan(text: string): { findings?: { ruleId?: string; reachability?: string }[] } {
  let doc: unknown;
  try {
    doc = JSON.parse(text) as unknown;
  } catch {
    fail('cannot read bumps file (FULLSHIELD_EXPERIMENTAL_BUMP_PR)');
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    fail('cannot read bumps file (FULLSHIELD_EXPERIMENTAL_BUMP_PR)');
  }
  return doc;
}

function countSkippedNotImported(findings: readonly { ruleId?: string; reachability?: string }[]): number {
  let count = 0;
  for (const finding of findings) {
    if (finding.ruleId === 'DEPS-VULN-001' && finding.reachability === 'not-imported') {count += 1;}
  }
  return count;
}

function groupBumps(rows: readonly RankedBump[]): RankedBump[] {
  const groups = new Map<string, RankedBump>();
  for (const row of rows) {
    const key = `${row.name}\0${row.to}`;
    const existing = groups.get(key);
    if (existing === undefined) {
      groups.set(key, { ...row, clears: 1 });
      continue;
    }
    existing.clears = (existing.clears ?? 1) + 1;
  }
  return [...groups.values()].map((row, index) => ({ ...row, rank: index + 1 }));
}

async function scriptsFor(cwd: string, name: string): Promise<{ hook: string; source: string }[]> {
  let text: string;
  try {
    text = await readFile(join(cwd, 'node_modules', name, 'package.json'), 'utf8');
  } catch {
    return [];
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return [];
  }
  const scripts = asRecord(asRecord(raw)?.scripts);
  if (scripts === undefined) {return [];}
  const out: { hook: string; source: string }[] = [];
  for (const hook of SCRIPT_HOOKS) {
    const source = scripts[hook];
    if (typeof source === 'string') {out.push({ hook, source });}
  }
  return out;
}

async function readInstallScripts(cwd: string, names: readonly string[]): Promise<InstallScriptReport[]> {
  const out: InstallScriptReport[] = [];
  for (const name of names) {
    out.push({ name, scripts: await scriptsFor(cwd, name) });
  }
  return out;
}

function attestationState(raw: unknown, version: string): 'absent' | 'present' | 'unknown' {
  const versions = asRecord(asRecord(raw)?.versions);
  const entry = versions === undefined ? undefined : asRecord(versions[version]);
  if (entry === undefined) {return 'unknown';}
  const dist = asRecord(entry.dist);
  if (dist === undefined || dist.attestations === undefined || dist.attestations === null) {return 'absent';}
  return 'present';
}

async function targetProvenance(
  cacheDir: string,
  name: string,
  version: string,
): Promise<'absent' | 'present' | 'unknown'> {
  let text: string;
  try {
    text = await readFile(registryCachePath(cacheDir, name), 'utf8');
  } catch {
    return 'unknown';
  }
  try {
    return attestationState(JSON.parse(text) as unknown, version);
  } catch {
    return 'unknown';
  }
}

async function applyProvenance(
  rows: readonly RankedBump[],
  cacheDir: string,
): Promise<{ bumps: RankedBump[]; provenanceBlocked: ProvenanceBlock[] }> {
  if (process.env.FULLSHIELD_EXPERIMENTAL_PROVENANCE !== '1') {
    return { bumps: [...rows], provenanceBlocked: [] };
  }
  const bumps: RankedBump[] = [];
  const provenanceBlocked: ProvenanceBlock[] = [];
  for (const row of rows) {
    const state = await targetProvenance(cacheDir, row.name, row.to);
    if (state === 'absent') {
      provenanceBlocked.push({ name: row.name, to: row.to, reason: 'absent' });
      continue;
    }
    bumps.push(row);
  }
  return { bumps: bumps.map((row, index) => ({ ...row, rank: index + 1 })), provenanceBlocked };
}

export async function buildBumpPlan(text: string, cwd: string, cacheDir = defaultCacheDir()): Promise<BumpPlan> {
  const doc = parseScan(text);
  const grouped = groupBumps(rankBumpsFromScan(doc));
  const filtered = await applyProvenance(grouped, cacheDir);
  const names = filtered.bumps.map((row) => row.name);
  return {
    bumps: filtered.bumps,
    skippedNotImported: countSkippedNotImported(doc.findings ?? []),
    installScripts: await readInstallScripts(cwd, names),
    provenanceBlocked: filtered.provenanceBlocked,
  };
}

export async function bumpPlanText(text: string, cwd: string, cacheDir = defaultCacheDir()): Promise<string> {
  return `${JSON.stringify(await buildBumpPlan(text, cwd, cacheDir))}\n`;
}
