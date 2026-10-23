/**
 * Phase 462. Env example drift.
 * Off unless FULLSHIELD_EXPERIMENTAL_ENVDRIFT=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not open a .env file. A computed key is an event, not an invented name.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ENVDRIFT';
export const ENV_MISSING = 'CONFIG-ENV-MISSING-001';
export const ENV_UNREAD = 'CONFIG-ENV-UNREAD-001';

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SourceFile {
  path: string;
  text: string;
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info';
  file: string;
  line: number;
  message: string;
}

export interface PhaseEvent {
  kind: 'parser-failure';
  file: string;
  line: number;
  reason: string;
}

export interface DriftResult {
  findings: PhaseFinding[];
  events: PhaseEvent[];
}

function ignored(path: string): boolean {
  const normalized = path.replace(/\\/g, '/');
  return normalized.endsWith('.test.ts') || normalized.endsWith('.spec.ts') || normalized.includes('/test/') || normalized.split('/').pop() === '.env';
}

function exampleKeys(text: string): string[] {
  const keys: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }
    const key = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(trimmed)?.[1];
    if (key !== undefined) {
      keys.push(key);
    }
  }
  return keys;
}

function astNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value;
}

function walkChild(child: unknown, visit: (node: TSESTree.Node) => void): void {
  if (Array.isArray(child)) {
    for (const item of child) {
      if (astNode(item)) {
        visit(item);
      }
    }
    return;
  }
  if (astNode(child)) {
    visit(child);
  }
}

function nodeLine(node: TSESTree.Node): number {
  return node.loc?.start.line ?? 1;
}

function isProcessEnv(node: TSESTree.MemberExpression): boolean {
  if (node.object.type !== 'MemberExpression') {
    return false;
  }
  const root = node.object.object;
  const mid = node.object.property;
  return root.type === 'Identifier' && root.name === 'process' && mid.type === 'Identifier' && mid.name === 'env';
}

function noteEnvMember(node: TSESTree.MemberExpression, file: string, events: PhaseEvent[], reads: Map<string, number>): void {
  if (!isProcessEnv(node)) {
    return;
  }
  if (node.computed && node.property.type !== 'Literal') {
    events.push({ kind: 'parser-failure', file, line: nodeLine(node), reason: 'computed process.env key' });
    return;
  }
  if (!node.computed && node.property.type === 'Identifier') {
    reads.set(node.property.name, nodeLine(node));
    return;
  }
  if (node.property.type === 'Literal' && typeof node.property.value === 'string') {
    reads.set(node.property.value, nodeLine(node));
  }
}

function visitEnv(node: TSESTree.Node, file: string, events: PhaseEvent[], reads: Map<string, number>): void {
  if (node.type === 'MemberExpression') {
    noteEnvMember(node, file, events, reads);
  }
  for (const child of Object.values(node as unknown as Record<string, unknown>)) {
    walkChild(child, (item) => {
      visitEnv(item, file, events, reads);
    });
  }
}

function envReads(file: string, text: string, events: PhaseEvent[]): Map<string, number> {
  const reads = new Map<string, number>();
  let ast: TSESTree.Program;
  try {
    ast = parse(text, { loc: true, range: false, jsx: false });
  } catch {
    events.push({ kind: 'parser-failure', file, line: 1, reason: 'parse failure' });
    return reads;
  }
  visitEnv(ast, file, events, reads);
  return reads;
}

export function diffEnv(files: readonly SourceFile[], example: string, schemaKeys: readonly string[] = [], baseline: readonly PhaseFinding[] = []): DriftResult {
  if (!enabled()) {
    return { findings: [...baseline], events: [] };
  }
  const events: PhaseEvent[] = [];
  const reads = new Map<string, { file: string; line: number }>();
  for (const file of files) {
    if (ignored(file.path)) {
      continue;
    }
    for (const [name, line] of envReads(file.path, file.text, events)) {
      if (!reads.has(name)) {
        reads.set(name, { file: file.path, line });
      }
    }
  }
  const known = new Set([...exampleKeys(example), ...schemaKeys]);
  const findings: PhaseFinding[] = [...baseline];
  for (const [name, where] of reads) {
    if (!known.has(name)) {
      findings.push({ ruleId: ENV_MISSING, severity: 'info', file: where.file, line: where.line, message: `${name} has no example key` });
    }
  }
  for (const key of known) {
    if (!reads.has(key) && !schemaKeys.includes(key)) {
      findings.push({ ruleId: ENV_UNREAD, severity: 'info', file: '.env.example', line: 1, message: `${key} has no read in the scan set` });
    }
  }
  return { findings, events };
}
