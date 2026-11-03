import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../core/finding.js';

export const EVIDENCE_FILE = '.fullshield/evidence.json';

export interface EvidenceFile {
  files: string[];
  confirmed?: string[];
}

export interface RecordedRun {
  files: readonly string[];
  confirmed: readonly string[];
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) {return [];}
  return value.filter((item): item is string => typeof item === 'string' && item.length > 0);
}

/** A missing or unreadable file leaves findings unchanged. */
export async function readEvidence(cwd: string): Promise<RecordedRun | undefined> {
  try {
    const text = await readFile(join(cwd, EVIDENCE_FILE), 'utf8');
    const parsed = JSON.parse(text) as { files?: unknown; confirmed?: unknown };
    const files = stringList(parsed.files);
    if (files.length === 0) {return undefined;}
    return { files, confirmed: stringList(parsed.confirmed) };
  } catch {
    return undefined;
  }
}

/** Files absent from a non-empty record drop to info and do not fail the gate. */
export function applyRecordedEvidence(
  findings: readonly Finding[],
  executed: readonly string[],
  confirmed: readonly string[] = [],
): Finding[] {
  if (executed.length === 0) {return [...findings];}
  const seen = new Set(executed.map((file) => file.split('\\').join('/')));
  const proven = new Set(confirmed.map((file) => file.split('\\').join('/')));
  return findings.map((finding) => {
    const file = (finding.file ?? '').split('\\').join('/');
    if (file.length > 0 && seen.has(file) && proven.has(file)) {
      return { ...finding, evidence: 'prioritized' };
    }
    if (file.length === 0 || seen.has(file)) {return finding;}
    return { ...finding, severity: 'info', gate: false };
  });
}
