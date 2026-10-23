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

export function scanWorkflow(file: string, text: string, files: Readonly<Record<string, string>> = {}, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const root = asRecord(parseYaml(text) as unknown);
  if (root === null) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  const target = onTarget(root);
  walkSteps(root, (step) => {
    if (typeof step.run === 'string') {
      const hit = extractExpressions(step.run).some(untrusted);
      if (hit) {
        findings.push({ ruleId: GHA_INJECT, severity: 'high', file, line: lineOf(text, 'run:'), message: 'run step interpolates an untrusted github.event field' });
      }
    }
    const uses = typeof step.uses === 'string' ? step.uses : '';
    const withBlock = asRecord(step.with);
    if (target && uses.includes('actions/checkout')) {
      const ref = typeof withBlock?.ref === 'string' ? withBlock.ref : '';
      if (ref.includes('pull_request.head')) {
        findings.push({
          ruleId: GHA_TARGET,
          severity: 'high',
          file,
          line: lineOf(text, 'pull_request'),
          message: 'the risk is executing the PR',
        });
      }
    }
    const key = typeof withBlock?.key === 'string' ? withBlock.key : '';
    const expressions = extractExpressions(key);
    const mutable = expressions.some((item) => item.includes('github.event.') || item.includes('pull_request'));
    const onlySha = expressions.length > 0 && expressions.every((item) => item.trim() === 'github.sha');
    if (mutable && !onlySha) {
      findings.push({ ruleId: GHA_CACHE, severity: 'medium', file, line: lineOf(text, 'key:'), message: 'cache key includes a mutable PR ref' });
    }
    const path = typeof withBlock?.path === 'string' ? withBlock.path : '';
    if (path === '.env' || path.endsWith('/.env')) {
      const body = files[path] ?? files['.env'];
      if (body !== undefined && SECRET.test(body)) {
        const token = SECRET.exec(body)?.[0] ?? '';
        findings.push({ ruleId: 'SECRET-AWS-001', severity: 'high', file, line: lineOf(text, '.env'), message: 'artifact path matches a secret', snippet: `${token.slice(0, 4)}****` });
      } else {
        findings.push({ ruleId: GHA_ENV_ARTIFACT, severity: 'info', file, line: lineOf(text, '.env'), message: 'artifact path is .env' });
      }
    }
  });
  return [...baseline, ...findings];
}
