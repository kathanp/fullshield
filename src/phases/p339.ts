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

export function sourceMapFindings(file: string, text: string, formats: readonly SecretFormat[], maxBytes = 1_000_000): MapResult {
  const empty: MapResult = { findings: [], events: [], fetched: false };
  if (!enabled()) {
    return empty;
  }
  if (text.length > maxBytes) {
    return { findings: [], events: [{ code: 271, file, detail: 'source map fuel exhausted' }], fetched: false };
  }
  const url = /sourceMappingURL=(\S+)/.exec(text)?.[1];
  if (url !== undefined && (url.startsWith('https://') || url.startsWith('http://'))) {
    return {
      findings: [{ ruleId: 'SECRETS-SRCMAP-001', severity: 'info', file, line: 1, message: 'sourceMappingURL was not fetched.' }],
      events: [],
      fetched: false,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { findings: [], events: [{ code: 271, file, detail: 'source map parse failed' }], fetched: false };
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return { findings: [], events: [{ code: 271, file, detail: 'source map parse failed' }], fetched: false };
  }
  const record = parsed as { sources?: unknown; sourcesContent?: unknown };
  const findings: MapFinding[] = [];
  if (Array.isArray(record.sources)) {
    for (const source of record.sources) {
      if (typeof source === 'string' && source.startsWith('/')) {
        findings.push({
          ruleId: 'SECRETS-SRCMAP-001',
          severity: 'info',
          file,
          line: 1,
          message: 'Source map lists an absolute path outside the repo.',
        });
      }
    }
  }
  if (!excluded(file) && Array.isArray(record.sourcesContent)) {
    record.sourcesContent.forEach((content, index) => {
      if (typeof content !== 'string' || matchGrammar(content, formats) === undefined) {
        return;
      }
      const source = Array.isArray(record.sources) && typeof record.sources[index] === 'string' ? record.sources[index] : file;
      const reported = typeof source === 'string' && !excluded(source) ? source : file;
      if (excluded(reported)) {
        return;
      }
      findings.push({
        ruleId: 'SECRETS-FORMAT-001',
        severity: 'high',
        file: reported,
        line: 1,
        message: 'sourcesContent matches a secret format.',
      });
    });
  }
  return { findings, events: [], fetched: false };
}
