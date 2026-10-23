/**
 * Phase 454. GitHub Actions expression edges.
 * Off unless FULLSHIELD_EXPERIMENTAL_GHAEXPR=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Expressions are parsed, including nested braces. This module does not call GitHub.
 */
import { parse as parseYaml } from 'yaml';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GHAEXPR';
export const GHA_INJECT = 'CI-GHA-INJECT-001';
export const GHA_TARGET = 'CI-GHA-TARGET-001';
export const GHA_CACHE = 'CI-GHA-CACHE-001';
const GHA_ENV_ARTIFACT = 'CI-GHA-ARTIFACT-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

function extractExpressions(text: string): string[] {
  const found: string[] = [];
  let i = 0;
  while (i < text.length) {
    const start = text.indexOf('${{', i);
    if (start < 0) {
      break;
    }
    let depth = 1;
    let j = start + 3;
    while (j < text.length && depth > 0) {
      if (text.startsWith('${{', j)) {
        depth += 1;
        j += 3;
        continue;
      }
      if (text.startsWith('}}', j)) {
        depth -= 1;
        j += 2;
        continue;
      }
      j += 1;
    }
    found.push(text.slice(start + 3, Math.max(start + 3, j - 2)).trim());
    i = j;
  }
  return found;
}

function untrusted(expression: string): boolean {
  return expression.includes('github.event.');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function onTarget(root: Record<string, unknown>): boolean {
  const on = root.on ?? root['true'];
  if (typeof on === 'string') {
    return on === 'pull_request_target';
  }
  const record = asRecord(on);
  if (record === null) {
    return false;
  }
  return Object.prototype.hasOwnProperty.call(record, 'pull_request_target');
}

function walkSteps(value: unknown, visit: (step: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      walkSteps(item, visit);
    }
    return;
  }
  const record = asRecord(value);
  if (record === null) {
    return;
  }
  if (typeof record.run === 'string' || typeof record.uses === 'string') {
    visit(record);
  }
  for (const child of Object.values(record)) {
    walkSteps(child, visit);
  }
}

function lineOf(text: string, needle: string): number {
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index < 0 ? 1 : index + 1;
}

interface WorkflowScan {
  file: string;
  text: string;
  files: Readonly<Record<string, string>>;
  target: boolean;
  findings: PhaseFinding[];
}

function stringField(record: Record<string, unknown> | null, key: string): string {
  const value = record?.[key];
  if (typeof value === 'string') {
    return value;
  }
  return '';
}

function noteRun(step: Record<string, unknown>, scan: WorkflowScan): void {
  if (typeof step.run !== 'string') {
    return;
  }
  if (!extractExpressions(step.run).some(untrusted)) {
    return;
  }
  scan.findings.push({ ruleId: GHA_INJECT, severity: 'high', file: scan.file, line: lineOf(scan.text, 'run:'), message: 'run step interpolates an untrusted github.event field' });
}

function noteCheckout(step: Record<string, unknown>, withBlock: Record<string, unknown> | null, scan: WorkflowScan): void {
  const uses = typeof step.uses === 'string' ? step.uses : '';
  if (!scan.target || !uses.includes('actions/checkout')) {
    return;
  }
  if (!stringField(withBlock, 'ref').includes('pull_request.head')) {
    return;
  }
  scan.findings.push({ ruleId: GHA_TARGET, severity: 'high', file: scan.file, line: lineOf(scan.text, 'pull_request'), message: 'the risk is executing the PR' });
}

function mutableKey(item: string): boolean {
  return item.includes('github.event.') || item.includes('pull_request');
}

function noteCache(withBlock: Record<string, unknown> | null, scan: WorkflowScan): void {
  const expressions = extractExpressions(stringField(withBlock, 'key'));
  const mutable = expressions.some(mutableKey);
  const onlySha = expressions.length > 0 && expressions.every((item) => item.trim() === 'github.sha');
  if (mutable && !onlySha) {
    scan.findings.push({ ruleId: GHA_CACHE, severity: 'medium', file: scan.file, line: lineOf(scan.text, 'key:'), message: 'cache key includes a mutable PR ref' });
  }
}

function envPath(path: string): boolean {
  return path === '.env' || path.endsWith('/.env');
}

function noteEnvArtifact(withBlock: Record<string, unknown> | null, scan: WorkflowScan): void {
  const path = stringField(withBlock, 'path');
  if (!envPath(path)) {
    return;
  }
  const body = scan.files[path] ?? scan.files['.env'];
  if (body === undefined || !SECRET.test(body)) {
    scan.findings.push({ ruleId: GHA_ENV_ARTIFACT, severity: 'info', file: scan.file, line: lineOf(scan.text, '.env'), message: 'artifact path is .env' });
    return;
  }
  const token = SECRET.exec(body)?.[0] ?? '';
  scan.findings.push({ ruleId: 'SECRET-AWS-001', severity: 'high', file: scan.file, line: lineOf(scan.text, '.env'), message: 'artifact path matches a secret', snippet: `${token.slice(0, 4)}****` });
}

function noteStep(step: Record<string, unknown>, scan: WorkflowScan): void {
  const withBlock = asRecord(step.with);
  noteRun(step, scan);
  noteCheckout(step, withBlock, scan);
  noteCache(withBlock, scan);
  noteEnvArtifact(withBlock, scan);
}

export function scanWorkflow(file: string, text: string, files: Readonly<Record<string, string>> = {}, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const root = asRecord(parseYaml(text) as unknown);
  if (root === null) {
    return [...baseline];
  }
  const scan: WorkflowScan = { file, text, files, target: onTarget(root), findings: [] };
  walkSteps(root, (step) => {
    noteStep(step, scan);
  });
  return [...baseline, ...scan.findings];
}
