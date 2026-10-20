import { readFile } from 'node:fs/promises';

import type { Finding } from '../core/finding.js';
import { dedupeIngested } from './dedupe.js';
import { IngestError } from './error.js';
import type { IngestItem } from './item.js';
import { parseIngestText } from './parse.js';

interface IngestGroup {
  source: string;
  findings: Finding[];
}

export interface IngestLoad {
  findings: Finding[];
  groups: IngestGroup[];
  errors: IngestError[];
}

export async function ingestLocalFiles(files: readonly string[]): Promise<IngestLoad> {
  const errors: IngestError[] = [];
  const items: IngestItem[] = [];
  const groups: IngestGroup[] = [];
  for (const file of files) {
    const text = await readText(file, errors);
    if (text === undefined) {continue;}
    try {
      const parsed = parseIngestText(file, text);
      items.push(...parsed);
      remember(groups, parsed);
    } catch (error) {
      errors.push(error instanceof IngestError ? error : new IngestError(file, 'unreadable'));
    }
  }
  return { findings: dedupeIngested(items), groups, errors };
}

async function readText(file: string, errors: IngestError[]): Promise<string | undefined> {
  try {
    return await readFile(file, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unreadable';
    errors.push(new IngestError(file, message));
    return undefined;
  }
}

function remember(groups: IngestGroup[], parsed: readonly IngestItem[]): void {
  for (const item of parsed) {
    const source = item.finding.source ?? 'external';
    const copy = copyFinding(item.finding);
    const existing = groups.find((group) => group.source === source);
    if (existing === undefined) {groups.push({ source, findings: [copy] });}
    else {existing.findings.push(copy);}
  }
}

function copyFinding(finding: Finding): Finding {
  return {
    ...finding,
    sources: finding.sources?.slice(),
    externalRuleIds: finding.externalRuleIds?.slice(),
  };
}
