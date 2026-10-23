import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

/** Phase 253. One level of call-site sensitivity. Cap 10, then sound. */
export const CONTEXT_FLAG = 'FULLSHIELD_EXPERIMENTAL_CONTEXT';

export function contextEnabled(): boolean {
  return process.env[CONTEXT_FLAG] === '1';
}

export interface CallSiteFinding {
  line: number;
  callee: string;
}

type ArgKind = { kind: 'param'; index: number } | { kind: 'tainted' } | { kind: 'literal' } | { kind: 'other' };

interface CallEdge {
  callee: string;
  args: ArgKind[];
  line: number;
}

interface FnFact {
  name: string;
  params: string[];
  directSinks: Set<number>;
  calls: CallEdge[];
}

const SINK_NAMES = new Set(['query', 'exec', 'eval']);

function isRequest(node: TSESTree.Node): boolean {
  let current: TSESTree.Node = node;
  while (current.type === 'MemberExpression') {current = current.object;}
  return current.type === 'Identifier' && current.name === 'req';
}

function classifyArg(node: TSESTree.Node, params: readonly string[]): ArgKind {
  if (node.type === 'Literal' || node.type === 'TemplateLiteral') {return { kind: 'literal' };}
  if (isRequest(node)) {return { kind: 'tainted' };}
  if (node.type === 'Identifier') {
    const index = params.indexOf(node.name);
    if (index >= 0) {return { kind: 'param', index };}
  }
  if (node.type === 'BinaryExpression') {
    const left = classifyArg(node.left, params);
    const right = classifyArg(node.right, params);
    if (left.kind === 'tainted' || right.kind === 'tainted') {return { kind: 'tainted' };}
    if (left.kind === 'param') {return left;}
    if (right.kind === 'param') {return right;}
  }
  return { kind: 'other' };
}

function collect(program: TSESTree.Program): { fns: Map<string, FnFact>; entries: CallEdge[] } {
  const fns = new Map<string, FnFact>();
  const entries: CallEdge[] = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {
      const params = stmt.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : []));
      const fact: FnFact = { name: stmt.id.name, params, directSinks: new Set(), calls: [] };
      walkFn(stmt.body, fact);
      fns.set(fact.name, fact);
    }
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      entries.push(callEdge(stmt.expression, [], stmt.expression.loc?.start.line ?? 1));
    }
  }
  return { fns, entries };
}

function isAstNode(value: unknown): value is TSESTree.Node {
  return value !== null && typeof value === 'object' && 'type' in value;
}

function walkAst(node: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  for (const key of Object.keys(node)) {
    if (key === 'parent') {continue;}
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) {visit(item);}
      }
    } else if (isAstNode(value)) {
      visit(value);
    }
  }
}

function isSinkCall(node: TSESTree.CallExpression): boolean {
  return node.callee.type === 'MemberExpression'
    && node.callee.property.type === 'Identifier'
    && SINK_NAMES.has(node.callee.property.name);
}

function noteCall(node: TSESTree.CallExpression, fact: FnFact): void {
  const edge = callEdge(node, fact.params, node.loc?.start.line ?? 1);
  if (edge.callee !== '' && !SINK_NAMES.has(edge.callee)) {fact.calls.push(edge);}
  if (!isSinkCall(node)) {return;}
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    const kind = classifyArg(arg, fact.params);
    if (kind.kind === 'param') {fact.directSinks.add(kind.index);}
  }
}

function walkNode(node: TSESTree.Node, fact: FnFact): void {
  if (node.type === 'CallExpression') {noteCall(node, fact);}
  walkAst(node, (child) => { walkNode(child, fact); });
}

function walkFn(body: TSESTree.BlockStatement, fact: FnFact): void {
  walkNode(body, fact);
}

function callEdge(node: TSESTree.CallExpression, params: readonly string[], line: number): CallEdge {
  let callee = '';
  if (node.callee.type === 'Identifier') {callee = node.callee.name;}
  else if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier') {
    callee = node.callee.property.name;
  }
  const args = node.arguments.map((arg) => (arg.type === 'SpreadElement' ? { kind: 'other' as const } : classifyArg(arg, params)));
  return { callee, args, line };
}

/** Param indexes that reach a sink. Past `cap` rounds, every param flows (sound). */
function sinkParams(fns: ReadonlyMap<string, FnFact>, cap = 10): Map<string, Set<number>> {
  const summary = new Map<string, Set<number>>();
  for (const [name, fact] of fns) {summary.set(name, new Set(fact.directSinks));}
  let saturated = false;
  for (let round = 0; round < cap; round += 1) {
    let changed = false;
    for (const fact of fns.values()) {
      const mine = summary.get(fact.name) ?? new Set<number>();
      for (const call of fact.calls) {
        const callee = summary.get(call.callee);
        if (callee === undefined) {continue;}
        call.args.forEach((arg, index) => {
          if (!callee.has(index) || arg.kind !== 'param') {return;}
          if (!mine.has(arg.index)) {
            mine.add(arg.index);
            changed = true;
          }
        });
      }
      summary.set(fact.name, mine);
    }
    if (!changed) {return summary;}
    if (round === cap - 1) {saturated = true;}
  }
  if (saturated) {
    for (const fact of fns.values()) {
      const mine = summary.get(fact.name) ?? new Set<number>();
      fact.params.forEach((_name, index) => mine.add(index));
      summary.set(fact.name, mine);
    }
  }
  return summary;
}

export function contextFindings(source: string, cap = 10): CallSiteFinding[] {
  if (!contextEnabled()) {return [];}
  const program = parse(source, {
    loc: true,
    range: false,
    jsx: false,
    comment: false,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
  const { fns, entries } = collect(program);
  const summary = sinkParams(fns, cap);
  const findings: CallSiteFinding[] = [];
  for (const entry of entries) {
    const sinks = summary.get(entry.callee);
    if (sinks === undefined) {continue;}
    const tainted = entry.args.some((arg, index) => sinks.has(index) && arg.kind === 'tainted');
    if (tainted) {findings.push({ line: entry.line, callee: entry.callee });}
  }
  return findings;
}
