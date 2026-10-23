/**
 * Phase 334. Secrets in structured text.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETDOCS=1.
 * In-tree parsers. A parse failure scans the file as text and records a 271 event.
 */

import { entropyReject } from './p333.js';
import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETDOCS';
const PLACEHOLDERS = ['changeme', 'password', 'secret', 'example', 'test', 'todo', 'placeholder'] as const;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const SENSITIVE = new Set(['password', 'secret', 'token']);

export interface DocFinding {
  ruleId: string;
  severity: 'info' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export interface DocResult {
  findings: DocFinding[];
  events: { code: 271; file: string; detail: string }[];
}

function excluded(file: string): boolean {
  const path = file.replaceAll('\\', '/');
  return path.includes('/models/') || path.startsWith('models/') || path.includes('/test/fixtures/') || path.startsWith('test/fixtures/');
}

function formatFinding(file: string, line: number, text: string, formats: readonly SecretFormat[]): DocFinding | undefined {
  const matched = matchGrammar(text, formats);
  if (matched === undefined) {
    return undefined;
  }
  return { ruleId: 'SECRETS-FORMAT-001', severity: 'high', file, line, message: `Structured text matches format ${matched.id}.`, witness: matched.id };
}

function quoteOdd(line: string): boolean {
  let count = 0;
  for (let index = 0; index < line.length; index += 1) {
    if (line[index] === '\\') {
      index += 1;
      continue;
    }
    if (line[index] === '"' || line[index] === "'") {
      count += 1;
    }
  }
  return count % 2 === 1;
}

function parseYamlSubset(text: string): { ok: true; pairs: { key: string; value: string; line: number }[]; comments: { text: string; line: number }[] } | { ok: false } {
  const pairs: { key: string; value: string; line: number }[] = [];
  const comments: { text: string; line: number }[] = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.startsWith('\t') || quoteOdd(line)) {
      return { ok: false };
    }
    const hash = line.indexOf('#');
    const code = hash >= 0 ? line.slice(0, hash) : line;
    if (hash >= 0) {
      comments.push({ text: line.slice(hash + 1), line: index + 1 });
    }
    const colon = code.indexOf(':');
    if (colon < 0) {
      continue;
    }
    const key = code.slice(0, colon).trim();
    const value = code.slice(colon + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key.length > 0) {
      pairs.push({ key, value, line: index + 1 });
    }
  }
  return { ok: true, pairs, comments };
}

function keyFinding(file: string, line: number, key: string, value: string, formats: readonly SecretFormat[]): DocFinding | undefined {
  const formatted = formatFinding(file, line, value, formats);
  if (formatted !== undefined) {
    return formatted;
  }
  if (!SENSITIVE.has(key.toLowerCase())) {
    return undefined;
  }
  if (entropyReject({ span: value, file, line }) === undefined) {
    return { ruleId: 'SECRETS-ENTROPY-001', severity: 'medium', file, line, message: `Sensitive key ${key} has a high-entropy value.`, witness: 'shannon-v2' };
  }
  if ((PLACEHOLDERS as readonly string[]).includes(value.trim().toLowerCase())) {
    return { ruleId: 'SECRETS-PLACEHOLDER-001', severity: 'info', file, line, message: `${key} is a placeholder value.`, witness: 'placeholder' };
  }
  return undefined;
}

function textsFrom(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  return [];
}

function notebook(text: string): { ok: true; parts: string[] } | { ok: false } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { ok: false };
  }
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray((parsed as { cells?: unknown }).cells)) {
    return { ok: false };
  }
  const parts: string[] = [];
  for (const cell of (parsed as { cells: unknown[] }).cells) {
    if (typeof cell !== 'object' || cell === null) {
      continue;
    }
    const record = cell as { source?: unknown; outputs?: unknown };
    parts.push(...textsFrom(record.source));
    if (!Array.isArray(record.outputs)) {
      continue;
    }
    for (const output of record.outputs) {
      if (typeof output !== 'object' || output === null) {
        continue;
      }
      const row = output as { text?: unknown };
      parts.push(...textsFrom(row.text));
    }
  }
  return { ok: true, parts };
}

export function scanDocument(file: string, text: string, formats: readonly SecretFormat[]): DocResult {
  if (!enabled() || excluded(file)) {
    return { findings: [], events: [] };
  }
  const path = file.replaceAll('\\', '/');
  if (path.endsWith('.ipynb')) {
    const parsed = notebook(text);
    if (!parsed.ok) {
      const hit = formatFinding(file, 1, text, formats);
      return { findings: hit === undefined ? [] : [hit], events: [{ code: 271, file, detail: 'notebook parse failed' }] };
    }
    const findings: DocFinding[] = [];
    for (const part of parsed.parts) {
      const hit = formatFinding(file, 1, part, formats);
      if (hit !== undefined) {
        findings.push(hit);
      }
    }
    return { findings, events: [] };
  }
  const parsed = path.endsWith('.yaml') || path.endsWith('.yml') || path.endsWith('.toml') || path.endsWith('.ini') || path.endsWith('.properties')
    ? parseYamlSubset(text)
    : undefined;
  if (parsed === undefined) {
    const hit = formatFinding(file, 1, text, formats);
    return { findings: hit === undefined ? [] : [hit], events: [] };
  }
  if (!parsed.ok) {
    const hit = formatFinding(file, 1, text, formats);
    return { findings: hit === undefined ? [] : [hit], events: [{ code: 271, file, detail: 'structured parse failed' }] };
  }
  const findings: DocFinding[] = [];
  for (const pair of parsed.pairs) {
    const hit = keyFinding(file, pair.line, pair.key, pair.value, formats);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  for (const comment of parsed.comments) {
    const hit = formatFinding(file, comment.line, comment.text, formats);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return { findings, events: [] };
}
