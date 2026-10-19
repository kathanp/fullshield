import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Finding } from '../../core/finding.js';
import { rangeSatisfies } from '../deps/semver.js';

export interface ModelEntry {
  kind: 'source' | 'sink' | 'sanitizer' | 'validator';
  sinkClass: string;
  memberPath: string;
  argumentIndex: number;
  reference: string;
}

export interface ModelPack {
  package: string;
  versionRange: string;
  entries: ModelEntry[];
}

const KINDS = new Set(['source', 'sink', 'sanitizer', 'validator']);

export function parseModelPack(raw: unknown): ModelPack {
  if (raw === null || typeof raw !== 'object') throw new Error('model pack is not an object');
  const record = raw as Record<string, unknown>;
  if (typeof record.package !== 'string' || typeof record.versionRange !== 'string' || !Array.isArray(record.entries)) {
    throw new Error('model pack is missing package, versionRange, or entries');
  }
  const entries = record.entries.map((entry) => {
    if (entry === null || typeof entry !== 'object') throw new Error('model entry is not an object');
    const row = entry as Record<string, unknown>;
    if (typeof row.kind !== 'string' || !KINDS.has(row.kind)) throw new Error('model entry kind is invalid');
    if (typeof row.sinkClass !== 'string' || typeof row.memberPath !== 'string') {
      throw new Error('model entry is missing sinkClass or memberPath');
    }
    if (typeof row.argumentIndex !== 'number' || typeof row.reference !== 'string') {
      throw new Error('model entry is missing argumentIndex or reference');
    }
    return {
      kind: row.kind as ModelEntry['kind'],
      sinkClass: row.sinkClass,
      memberPath: row.memberPath,
      argumentIndex: row.argumentIndex,
      reference: row.reference,
    };
  });
  return { package: record.package, versionRange: record.versionRange, entries };
}

function modelsDir(): string {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const candidates = [join(here, '../../../models'), join(here, '../../models'), join(here, '../models')];
  return candidates.find((dir) => existsSync(dir)) ?? candidates[0] ?? 'models';
}

export async function loadModelPacks(): Promise<ModelPack[]> {
  const dir = modelsDir();
  const names = (await readdir(dir)).filter((name) => name.endsWith('.json')).sort();
  const packs: ModelPack[] = [];
  for (const name of names) {
    packs.push(parseModelPack(JSON.parse(await readFile(join(dir, name), 'utf8')) as unknown));
  }
  return packs;
}

const RULE_CLASS: Record<string, string> = {
  'SAST-SQLI-001': 'sqli',
  'SAST-NOSQLI-001': 'nosqli',
  'SAST-CMDI-001': 'cmdi',
  'SAST-PATH-001': 'path',
  'SAST-XSS-001': 'xss',
  'SAST-SSRF-001': 'ssrf',
};

/** A sanitizer pack entry clears a finding only when the call is in the same file. `.trim()` does not. */
export function modelSuppressReason(
  finding: Finding,
  source: string,
  packs: readonly ModelPack[],
  versions: ReadonlyMap<string, string>,
): string | undefined {
  const sink = RULE_CLASS[finding.ruleId];
  if (sink === undefined) return undefined;
  for (const pack of packs) {
    const installed = versions.get(pack.package);
    if (installed === undefined || rangeSatisfies(pack.versionRange, installed) !== true) continue;
    for (const entry of pack.entries) {
      if (entry.kind !== 'sanitizer' && entry.kind !== 'validator') continue;
      if (entry.sinkClass !== sink) continue;
      if (source.includes(entry.memberPath)) return `model:${pack.package}`;
    }
  }
  return undefined;
}
