/**
 * Phase 461. Bundler env inlining.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEFINEENV=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not read the process environment to fill a value and does not run the bundler.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEFINEENV';
export const ENV_CLIENT_RULE = 'SAST-ENV-CLIENT-001';

const SECRET_NAMES = ['SECRET', 'PASSWORD', 'TOKEN', 'API_KEY', 'PRIVATE_KEY', 'DATABASE_URL', 'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID'];
const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_'];

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SecretFormat {
  id: string;
  pattern: RegExp;
  publicByDesign: boolean;
}

export interface PhaseFinding {
  ruleId: typeof ENV_CLIENT_RULE;
  severity: 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet: string;
}

const DEFAULT_FORMATS: readonly SecretFormat[] = [{ id: 'aws-access-key', pattern: /\bAKIA[0-9A-Z]{16}\b/, publicByDesign: false }];

function propertyName(node: TSESTree.Node): string | null {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  return null;
}

function stringLiteral(node: TSESTree.Node | undefined): string | null {
  if (node !== undefined && node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  return null;
}

function envName(key: string): string | null {
  const member = /^process\.env\.(.+)$/.exec(key);
  if (member?.[1] !== undefined) {
    return member[1];
  }
  return key;
}

function classify(name: string, formats: readonly SecretFormat[]): 'high' | 'medium' | null {
  if (PUBLIC_PREFIXES.some((prefix) => name.startsWith(prefix))) {
    return null;
  }
  if (formats.some((format) => format.publicByDesign && format.pattern.test(name))) {
    return null;
  }
  if (SECRET_NAMES.some((item) => name === item || name.endsWith(`_${item}`))) {
    return 'high';
  }
  return 'medium';
}

interface Collected {
  target: 'client' | 'server' | 'unknown';
  names: Array<{ name: string; line: number; formatId: string }>;
}

function collect(text: string, formats: readonly SecretFormat[]): Collected {
  const ast = parse(text, { loc: true, range: false, jsx: false });
  const collected: Collected = { target: 'unknown', names: [] };
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'Property') {
      const key = propertyName(node.key);
      if (key === 'target' && node.value.type === 'Literal') {
        collected.target = node.value.value === 'node' ? 'server' : 'client';
      }
      if ((key === 'define' || key === 'env') && node.value.type === 'ObjectExpression') {
        for (const prop of node.value.properties) {
          if (prop.type !== 'Property') {
            continue;
          }
          const raw = propertyName(prop.key);
          const name = raw === null ? null : envName(raw);
          if (name === null) {
            continue;
          }
          const value = stringLiteral(prop.value);
          const format = formats.find((item) => value !== null && item.pattern.test(value));
          if (format?.publicByDesign === true) {
            continue;
          }
          collected.names.push({ name, line: prop.loc?.start.line ?? 1, formatId: format?.id ?? 'name-only' });
        }
      }
    }
    for (const child of Object.values(node as unknown as Record<string, unknown>)) {
      if (Array.isArray(child)) {
        for (const item of child) {
          if (typeof item === 'object' && item !== null && 'type' in item) {
            visit(item as TSESTree.Node);
          }
        }
      } else if (typeof child === 'object' && child !== null && 'type' in child) {
        visit(child as TSESTree.Node);
      }
    }
  };
  visit(ast);
  return collected;
}

export function scanDefine(file: string, text: string, formats: readonly SecretFormat[] = DEFAULT_FORMATS, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  let collected: Collected;
  try {
    collected = collect(text, formats);
  } catch {
    return [...baseline];
  }
  if (collected.target === 'server') {
    return [...baseline];
  }
  const client = collected.target === 'client' || text.includes('env:');
  if (!client) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  for (const entry of collected.names) {
    const severity = classify(entry.name, formats);
    if (severity === null) {
      continue;
    }
    findings.push({
      ruleId: ENV_CLIENT_RULE,
      severity,
      file,
      line: entry.line,
      message: `client inline ${entry.name} (${entry.formatId})`,
      snippet: '****',
    });
  }
  return [...baseline, ...findings];
}
