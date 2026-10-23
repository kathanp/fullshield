/**
 * Phase 362. Time and locale gates in lifecycle scripts.
 * Off unless FULLSHIELD_EXPERIMENTAL_TIMEGATE=1.
 * Parses only. Does not run the branch.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TIMEGATE';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type SinkClass = 'net' | 'fs-write' | 'process-exit' | 'shell';

export interface TimeGateFinding {
  ruleId: 'DEPS-TIMEGATE-001';
  severity: 'medium';
  packageName: string;
  condition: string;
  sinkClass: SinkClass;
  message: string;
}

const NET = new Set(['fetch', 'request', 'get', 'connect', 'createConnection']);
const FS_WRITE = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']);
const SHELL = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);

function isNode(value: unknown): value is TSESTree.Node {
  if (typeof value !== 'object' || value === null || !('type' in value)) {return false;}
  return typeof value.type === 'string';
}

function children(node: TSESTree.Node): TSESTree.Node[] {
  const out: TSESTree.Node[] = [];
  const record = node as unknown as Record<string, unknown>;
  for (const value of Object.values(record)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) {
          out.push(item);
        }
      }
    } else if (isNode(value)) {
      out.push(value);
    }
  }
  return out;
}

function calleeName(node: TSESTree.Node): string | null {
  if (node.type !== 'CallExpression') {
    return null;
  }
  const callee = node.callee;
  if (callee.type === 'Identifier') {
    return callee.name;
  }
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && !callee.computed) {
    return callee.property.name;
  }
  return null;
}

function sinkClass(node: TSESTree.Node): SinkClass | null {
  const name = calleeName(node);
  if (name === null) {
    return null;
  }
  if (name === 'exit') {
    return 'process-exit';
  }
  if (NET.has(name)) {
    return 'net';
  }
  if (FS_WRITE.has(name)) {
    return 'fs-write';
  }
  if (SHELL.has(name)) {
    return 'shell';
  }
  return null;
}

function findSink(node: TSESTree.Node): SinkClass | null {
  const direct = sinkClass(node);
  if (direct !== null) {
    return direct;
  }
  for (const child of children(node)) {
    const hit = findSink(child);
    if (hit !== null) {
      return hit;
    }
  }
  return null;
}

function memberText(node: TSESTree.MemberExpression): string | null {
  if (node.property.type !== 'Identifier' || node.computed) {
    return null;
  }
  if (node.object.type === 'Identifier') {
    return `${node.object.name}.${node.property.name}`;
  }
  if (node.object.type === 'MemberExpression') {
    const inner = memberText(node.object);
    if (inner === null) {
      return null;
    }
    return `${inner}.${node.property.name}`;
  }
  return null;
}

/** Condition shapes this phase cares about. `process.version` is intentionally absent. */
function conditionShape(node: TSESTree.Node): string | null {
  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Date') {
    return 'Date';
  }
  if (node.type === 'Identifier' && node.name === 'Intl') {
    return 'Intl';
  }
  if (node.type === 'MemberExpression') {
    const text = memberText(node);
    if (text === 'process.env.TZ' || text === 'process.env.LANG') {
      return text;
    }
    if (text !== null && (text.startsWith('Date') || text.startsWith('Intl'))) {
      return text.startsWith('Date') ? 'Date' : 'Intl';
    }
  }
  for (const child of children(node)) {
    const hit = conditionShape(child);
    if (hit !== null) {
      return hit;
    }
  }
  return null;
}

function scan(node: TSESTree.Node, found: { condition: string; sinkClass: SinkClass } | null): { condition: string; sinkClass: SinkClass } | null {
  if (found !== null) {
    return found;
  }
  if (node.type === 'IfStatement') {
    const condition = conditionShape(node.test);
    const consequent = findSink(node.consequent);
    const alternate = node.alternate === null ? null : findSink(node.alternate);
    const sink = consequent ?? alternate;
    if (condition !== null && sink !== null) {
      return { condition, sinkClass: sink };
    }
  }
  let current: { condition: string; sinkClass: SinkClass } | null = found;
  for (const child of children(node)) {
    current = scan(child, current);
  }
  return current;
}

export function timeGates(packageName: string, source: string): TimeGateFinding[] {
  if (!enabled()) {
    return [];
  }
  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: false, range: false, jsx: false });
  } catch {
    return [];
  }
  const hit = scan(ast, null);
  if (hit === null) {
    return [];
  }
  return [
    {
      ruleId: 'DEPS-TIMEGATE-001',
      severity: 'medium',
      packageName,
      condition: hit.condition,
      sinkClass: hit.sinkClass,
      message: `Condition shape ${hit.condition} dominates a ${hit.sinkClass} sink. This is a time or locale branch, not a label for the package.`,
    },
  ];
}
