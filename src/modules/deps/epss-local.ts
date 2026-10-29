import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { Finding, Severity } from '../../core/finding.js';

const EPSS_LOCAL_FLAG = 'FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL';

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

export interface EpssRow {
  epss: number;
  kev: boolean;
}

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function epssPriority(input: {
  epss: number;
  kev: boolean;
  reachability?: string;
  severity: Severity;
}): number {
  const reach = input.reachability === 'reachable' ? 10 : 0;
  return (input.kev ? 1000 : 0) + Math.round(input.epss * 100) + reach + SEVERITY_POINTS[input.severity];
}

export function parseEpssTable(text: string): Record<string, EpssRow> {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    fail(`epss file is not JSON (${EPSS_LOCAL_FLAG})`);
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    fail(`epss file must be an object (${EPSS_LOCAL_FLAG})`);
  }
  const out: Record<string, EpssRow> = {};
  for (const [id, value] of Object.entries(raw)) {
    if (typeof value !== 'object' || value === null) {
      fail(`epss must be from 0 to 1 (${EPSS_LOCAL_FLAG})`);
    }
    const epss = (value as { epss?: unknown }).epss;
    const kev = (value as { kev?: unknown }).kev;
    if (typeof epss !== 'number' || epss < 0 || epss > 1) {
      fail(`epss must be from 0 to 1 (${EPSS_LOCAL_FLAG})`);
    }
    if (typeof kev !== 'boolean') {
      fail(`kev must be a boolean (${EPSS_LOCAL_FLAG})`);
    }
    out[id] = { epss, kev };
  }
  return out;
}

export function enrichEpss(findings: readonly Finding[], table: Record<string, EpssRow>): Finding[] {
  return findings.map((finding) => {
    const id = (finding.references ?? []).find((ref) => table[ref] !== undefined);
    if (id === undefined) {return finding;}
    const row = table[id];
    if (row === undefined) {return finding;}
    return {
      ...finding,
      epss: row.epss,
      kev: row.kev,
      epssPriority: epssPriority({
        epss: row.epss,
        kev: row.kev,
        reachability: finding.reachability,
        severity: finding.severity,
      }),
    };
  });
}

export async function readEpssTable(cwd: string, rel: string): Promise<Record<string, EpssRow>> {
  let text: string;
  try {
    text = await readFile(resolve(cwd, rel), 'utf8');
  } catch {
    fail(`cannot read epss file (${EPSS_LOCAL_FLAG})`);
  }
  return parseEpssTable(text);
}
