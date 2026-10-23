import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STRDOMAIN';

const SEGMENT_LIMIT = 8;

export type CharClass = 'any' | 'digits' | 'numeric' | 'letters' | 'no-quote' | 'no-dash' | 'path-sep-free';

export type Segment =
  | { kind: 'literal'; text: string }
  | { kind: 'tainted'; labels: string[]; charClass: CharClass }
  | { kind: 'unknown'; labels: string[] };

export interface AbstractString {
  segments: Segment[];
}

export type StringOp =
  | { op: 'concat'; right: AbstractString }
  | { op: 'upper' }
  | { op: 'lower' }
  | { op: 'slice' }
  | { op: 'replace'; pattern: string; replacement: string }
  | { op: 'join'; sep: string; parts: readonly AbstractString[] };

const DEFAULT_LABELS = ['sqli', 'cmdi', 'xss', 'ssrf', 'path'];

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function lit(text: string): AbstractString {
  return { segments: text === '' ? [] : [{ kind: 'literal', text }] };
}

export function tainted(labels: readonly string[], charClass: CharClass): AbstractString {
  return { segments: [{ kind: 'tainted', labels: [...labels], charClass }] };
}

export function concatAbs(left: AbstractString, right: AbstractString): AbstractString {
  if (!enabled()) {return left;}
  return { segments: normalize([...left.segments, ...right.segments]) };
}

function applyStringOp(value: AbstractString, op: StringOp): AbstractString {
  if (!enabled()) {return value;}
  if (op.op === 'concat') {return concatAbs(value, op.right);}
  if (op.op === 'upper' || op.op === 'lower') {return mapLiterals(value, (text) => (op.op === 'upper' ? text.toUpperCase() : text.toLowerCase()));}
  if (op.op === 'slice') {return widen(value);}
  if (op.op === 'replace') {return replaceLiteral(value, op.pattern, op.replacement);}
  const parts: Segment[] = [];
  op.parts.forEach((part, index) => {
    if (index > 0 && op.sep !== '') {parts.push({ kind: 'literal', text: op.sep });}
    parts.push(...part.segments);
  });
  return { segments: normalize(parts) };
}

export function evaluateProgram(
  source: string,
  options?: { bindings?: Readonly<Record<string, { labels: readonly string[]; charClass: CharClass }>> },
): AbstractString | null {
  if (!enabled()) {return null;}
  const program = parseProgram(source);
  if (program === null) {return null;}
  const env = new Map<string, AbstractString>();
  for (const [name, binding] of Object.entries(options?.bindings ?? {})) {
    env.set(name, tainted(binding.labels, binding.charClass));
  }
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration') {
      const returned = execBlock(stmt.body.body, env);
      if (returned !== null) {return returned;}
    }
  }
  return lit('');
}

/** Transfer function used by later phases. It does not consult this phase's flag. */
export function abstractExpression(node: TSESTree.Node, env: ReadonlyMap<string, AbstractString>): AbstractString {
  const current = stripNode(node);
  if (current.type === 'Literal' && typeof current.value === 'string') {return lit(current.value);}
  if (current.type === 'Literal' && typeof current.value === 'number') {return lit(String(current.value));}
  if (current.type === 'Identifier') {return env.get(current.name) ?? { segments: [] };}
  if (isRequestSource(current)) {return tainted(DEFAULT_LABELS, 'any');}
  if (current.type === 'TemplateLiteral') {
    let acc = lit('');
    current.quasis.forEach((quasi, index) => {
      acc = { segments: normalize([...acc.segments, ...lit(quasi.value.cooked ?? '').segments]) };
      const expr = current.expressions[index];
      if (expr !== undefined) {acc = { segments: normalize([...acc.segments, ...abstractExpression(expr, env).segments]) };}
    });
    return acc;
  }
  if (current.type === 'BinaryExpression' && current.operator === '+') {
    return { segments: normalize([...abstractExpression(current.left, env).segments, ...abstractExpression(current.right, env).segments]) };
  }
  if (current.type === 'CallExpression') {return evalCall(current, env);}
  if (current.type === 'MemberExpression' && current.property.type === 'Identifier') {
    return applyMember(abstractExpression(current.object, env), current);
  }
  return { segments: [] };
}

export function labelsOf(value: AbstractString): string[] {
  const labels = new Set<string>();
  for (const seg of value.segments) {
    if (seg.kind !== 'literal') {
      for (const label of seg.labels) {labels.add(label);}
    }
  }
  return [...labels];
}

function evalCall(call: TSESTree.CallExpression, env: ReadonlyMap<string, AbstractString>): AbstractString {
  const callee = stripNode(call.callee);
  const args = call.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [abstractExpression(arg, env)]));
  if (callee.type === 'Identifier' && (callee.name === 'Number' || callee.name === 'parseInt')) {
    return retaint(args[0] ?? { segments: [] }, 'numeric');
  }
  if (callee.type === 'Identifier' && callee.name === 'String') {return retaint(args[0] ?? { segments: [] }, 'any');}
  if (callee.type === 'MemberExpression') {return applyMember(abstractExpression(callee.object, env), callee, args, call);}
  return { segments: [] };
}

function applyMember(
  object: AbstractString,
  member: TSESTree.MemberExpression,
  args: readonly AbstractString[] = [],
  call?: TSESTree.CallExpression,
): AbstractString {
  const name = propName(member);
  if (name === 'toUpperCase') {return mapLiterals(object, (text) => text.toUpperCase());}
  if (name === 'toLowerCase') {return mapLiterals(object, (text) => text.toLowerCase());}
  if (name === 'slice' || name === 'substring') {return widen(object);}
  if (name === 'replace' && call !== undefined) {return applyReplace(object, call);}
  if (name === 'join') {
    const sep = args[0]?.segments[0];
    const sepText = sep !== undefined && sep.kind === 'literal' ? sep.text : ',';
    return applyStringOp(object, { op: 'join', sep: sepText, parts: [object] });
  }
  if (object.segments.some((seg) => seg.kind !== 'literal')) {return object;}
  return object;
}

function applyReplace(object: AbstractString, call: TSESTree.CallExpression): AbstractString {
  const pattern = call.arguments[0];
  const replacement = call.arguments[1];
  if (pattern === undefined || replacement === undefined || pattern.type === 'SpreadElement' || replacement.type === 'SpreadElement') {
    return object;
  }
  if (pattern.type === 'Literal' && typeof pattern.value === 'string' && replacement.type === 'Literal' && typeof replacement.value === 'string') {
    return replaceLiteral(object, pattern.value, replacement.value);
  }
  if (pattern.type === 'Literal' && 'regex' in pattern && pattern.regex !== null && pattern.regex !== undefined && replacement.type === 'Literal' && replacement.value === '') {
    const source = pattern.regex.pattern;
    if (source.includes("'") || source.includes('"') || source.includes('\\\\')) {
      return retaint(object, 'no-quote');
    }
  }
  return object;
}

function replaceLiteral(value: AbstractString, pattern: string, replacement: string): AbstractString {
  if (value.segments.every((seg) => seg.kind === 'literal')) {
    const text = value.segments.map((seg) => (seg.kind === 'literal' ? seg.text : '')).join('');
    return lit(text.replace(pattern, replacement));
  }
  return {
    segments: normalize(value.segments.map((seg) => {
      if (seg.kind !== 'literal') {return seg;}
      return { kind: 'literal' as const, text: seg.text.replace(pattern, replacement) };
    })),
  };
}

function retaint(value: AbstractString, charClass: CharClass): AbstractString {
  const labels = labelsOf(value);
  if (labels.length === 0) {return value;}
  return tainted(labels, charClass);
}

function mapLiterals(value: AbstractString, fn: (text: string) => string): AbstractString {
  return {
    segments: value.segments.map((seg) => (seg.kind === 'literal' ? { kind: 'literal', text: fn(seg.text) } : seg)),
  };
}

function widen(value: AbstractString): AbstractString {
  const labels = labelsOf(value);
  if (labels.length === 0) {
    const text = value.segments.map((seg) => (seg.kind === 'literal' ? seg.text : '')).join('');
    return lit(text);
  }
  return { segments: [{ kind: 'tainted', labels, charClass: 'any' }] };
}

function normalize(segments: readonly Segment[]): Segment[] {
  const merged: Segment[] = [];
  for (const seg of segments) {
    if (seg.kind === 'literal' && seg.text === '') {continue;}
    const prev = merged[merged.length - 1];
    if (prev !== undefined && prev.kind === 'literal' && seg.kind === 'literal') {
      merged[merged.length - 1] = { kind: 'literal', text: prev.text + seg.text };
      continue;
    }
    merged.push(seg.kind === 'literal' ? seg : { ...seg, labels: [...seg.labels] });
  }
  if (merged.length <= SEGMENT_LIMIT) {return merged;}
  return [{ kind: 'unknown', labels: labelsOf({ segments: merged }) }];
}

function execBlock(stmts: readonly TSESTree.Statement[], env: Map<string, AbstractString>): AbstractString | null {
  let returned: AbstractString | null = null;
  for (const stmt of stmts) {
    const value = execStmt(stmt, env);
    if (value !== null) {returned = value;}
  }
  return returned;
}

function execStmt(stmt: TSESTree.Statement, env: Map<string, AbstractString>): AbstractString | null {
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, abstractExpression(decl.init, env));}
    }
    return null;
  }
  if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'AssignmentExpression' && stmt.expression.left.type === 'Identifier') {
    env.set(stmt.expression.left.name, abstractExpression(stmt.expression.right, env));
    return null;
  }
  if (stmt.type === 'ReturnStatement' && stmt.argument !== null) {return abstractExpression(stmt.argument, env);}
  if (stmt.type === 'BlockStatement') {return execBlock(stmt.body, env);}
  if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {return execLoop(stmt, env);}
  if (stmt.type === 'IfStatement') {
    execStmt(stmt.consequent, env);
    if (stmt.alternate !== null) {execStmt(stmt.alternate, env);}
  }
  return null;
}

function execLoop(stmt: TSESTree.ForStatement | TSESTree.WhileStatement, env: Map<string, AbstractString>): AbstractString | null {
  if (stmt.type === 'ForStatement' && stmt.init !== null && stmt.init.type !== 'VariableDeclaration') {
    execStmt({ type: 'ExpressionStatement', expression: stmt.init } as TSESTree.ExpressionStatement, env);
  }
  if (stmt.type === 'ForStatement' && stmt.init !== null && stmt.init.type === 'VariableDeclaration') {execStmt(stmt.init, env);}
  const body = stmt.body.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
  let returned: AbstractString | null = null;
  for (let round = 0; round < 4; round += 1) {
    const before = snapshot(env);
    returned = execBlock(body, env) ?? returned;
    for (const [name, value] of env) {
      if ((before.get(name) ?? '') !== JSON.stringify(value)) {
        env.set(name, widenLoop(value));
      }
    }
    if (snapshot(env).size === before.size && [...env.keys()].every((name) => before.get(name) === JSON.stringify(env.get(name)))) {
      break;
    }
  }
  return returned;
}

function widenLoop(value: AbstractString): AbstractString {
  const labels = labelsOf(value);
  if (labels.length === 0) {return value;}
  return { segments: [{ kind: 'unknown', labels }] };
}

function snapshot(env: ReadonlyMap<string, AbstractString>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [name, value] of env) {out.set(name, JSON.stringify(value));}
  return out;
}
