/**
 * Phase 339. Source maps that ship original text.
 * Off unless FULLSHIELD_EXPERIMENTAL_SRCMAPSECRET=1.
 * Remote sourceMappingURL values are not fetched.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SRCMAPSECRET';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface MapFinding {
  ruleId: 'SECRETS-SRCMAP-001' | 'SECRETS-FORMAT-001';
  severity: 'info' | 'high';
  file: string;
  line: number;
  message: string;
}

export interface MapResult {
  findings: MapFinding[];
  events: { code: 271; file: string; detail: string }[];
  fetched: false;
}

function excluded(path: string): boolean {
  const normalized = path.replaceAll('\\', '/');
  return normalized.includes('/test/fixtures/') || normalized.startsWith('test/fixtures/');
}

function failedMap(file: string, detail: string): MapResult {
  return { findings: [], events: [{ code: 271, file, detail }], fetched: false };
}

function remoteMap(file: string, text: string): boolean {
  const url = /sourceMappingURL=(\S+)/.exec(text)?.[1];
  if (url === undefined) {
    return false;
  }
  return url.startsWith('https://') || url.startsWith('http://');
}

function absoluteSources(file: string, sources: unknown): MapFinding[] {
  if (!Array.isArray(sources)) {
    return [];
  }
  const findings: MapFinding[] = [];
  for (const source of sources) {
    if (typeof source === 'string' && source.startsWith('/')) {
      findings.push({ ruleId: 'SECRETS-SRCMAP-001', severity: 'info', file, line: 1, message: 'Source map lists an absolute path outside the repo.' });
    }
  }
  return findings;
}

function reportedFile(source: unknown, file: string): string {
  if (typeof source === 'string' && !excluded(source)) {
    return source;
  }
  return file;
}

function contentHit(content: unknown, source: unknown, file: string, formats: readonly SecretFormat[]): MapFinding | undefined {
  if (typeof content !== 'string' || matchGrammar(content, formats) === undefined) {
    return undefined;
  }
  const reported = reportedFile(source, file);
  if (excluded(reported)) {
    return undefined;
  }
  return { ruleId: 'SECRETS-FORMAT-001', severity: 'high', file: reported, line: 1, message: 'sourcesContent matches a secret format.' };
}

function contentFindings(file: string, record: { sources?: unknown; sourcesContent?: unknown }, formats: readonly SecretFormat[]): MapFinding[] {
  if (excluded(file) || !Array.isArray(record.sourcesContent)) {
    return [];
  }
  const findings: MapFinding[] = [];
  record.sourcesContent.forEach((content, index) => {
    const source = sourceName(record.sources, index, file);
    const hit = contentHit(content, source, file, formats);
    if (hit !== undefined) {
      findings.push(hit);
    }
  });
  return findings;
}

function isRecord(value: unknown): value is { sources?: unknown; sourcesContent?: unknown } {
  return typeof value === 'object' && value !== null;
}

function sourceName(sources: unknown, index: number, file: string): string {
  if (!isUnknownList(sources)) {
    return file;
  }
  const item = sources[index];
  return typeof item === 'string' ? item : file;
}

function isUnknownList(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function parsedRecord(text: string): { sources?: unknown; sourcesContent?: unknown } | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) {
    return undefined;
  }
  return parsed;
}

export function sourceMapFindings(file: string, text: string, formats: readonly SecretFormat[], maxBytes = 1_000_000): MapResult {
  const empty: MapResult = { findings: [], events: [], fetched: false };
  if (!enabled()) {
    return empty;
  }
  if (text.length > maxBytes) {
    return failedMap(file, 'source map fuel exhausted');
  }
  if (remoteMap(file, text)) {
    return { findings: [{ ruleId: 'SECRETS-SRCMAP-001', severity: 'info', file, line: 1, message: 'sourceMappingURL was not fetched.' }], events: [], fetched: false };
  }
  const record = parsedRecord(text);
  if (record === undefined) {
    return failedMap(file, 'source map parse failed');
  }
  return { findings: [...absoluteSources(file, record.sources), ...contentFindings(file, record, formats)], events: [], fetched: false };
}
