import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';
import { abstractExpression, labelsOf, type AbstractString, type CharClass, type Segment } from './p278.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SHELLCTX';

export type ShellContext = 'single' | 'double' | 'bare' | 'option';

export interface ShellFinding {
  file: string;
  line: number;
  ruleId: 'SAST-CMDI-001';
  shellContext: ShellContext;
}

interface Binding {
  tainted: boolean;
  charClass: CharClass;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeShell(source: string, options?: { file?: string }): { findings: ShellFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: ShellFinding[] = [];
  const bag: ShellWalk = { file, findings, walk: () => undefined };
  bag.walk = (stmts, env, params) => {
    for (const stmt of stmts) {walkShell(stmt, env, params, bag);}
  };
  bag.walk(program.body, new Map(), new Set());
  return { findings };
}

interface ShellWalk {
  file: string;
  findings: ShellFinding[];
  walk: (stmts: readonly TSESTree.Statement[], env: Map<string, Binding>, params: ReadonlySet<string>) => void;
}

function walkShell(stmt: TSESTree.Statement, env: Map<string, Binding>, params: ReadonlySet<string>, bag: ShellWalk): void {
  if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {walkShellFn(stmt, env, bag); return;}
  if (stmt.type === 'BlockStatement') {bag.walk(stmt.body, env, params); return;}
  if (stmt.type === 'IfStatement') {walkShellIf(stmt, env, params, bag); return;}
  if (stmt.type === 'VariableDeclaration') {bindShellVars(stmt, env); return;}
  if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
    noteCall(stmt.expression, env, bag.file, bag.findings);
  }
}

function walkShellFn(stmt: TSESTree.FunctionDeclaration, env: Map<string, Binding>, bag: ShellWalk): void {
  if (stmt.id === null) {return;}
  const names = new Set(stmt.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : [])));
  const next = new Map(env);
  for (const name of names) {next.set(name, { tainted: true, charClass: 'any' });}
  bag.walk(stmt.body.body, next, names);
}

function walkShellIf(stmt: TSESTree.IfStatement, env: Map<string, Binding>, params: ReadonlySet<string>, bag: ShellWalk): void {
  bag.walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env, params);
  if (stmt.alternate !== null) {bag.walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate], env, params);}
}

function bindShellVars(stmt: TSESTree.VariableDeclaration, env: Map<string, Binding>): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, bindingOf(decl.init, env));}
  }
}

function noteCall(
  call: TSESTree.CallExpression,
  env: ReadonlyMap<string, Binding>,
  file: string,
  findings: ShellFinding[],
): void {
  const name = calleeName(call.callee);
  if (name === null) {return;}
  if (name === 'execFile' || (name === 'spawn' && !shellTrue(call))) {
    noteArgv(call, env, file, findings);
    return;
  }
  if (name === 'exec' || name === 'execSync' || name === 'spawn') {
    const arg = call.arguments[0];
    if (arg === undefined || arg.type === 'SpreadElement') {return;}
    const value = abstractExpression(arg, stringEnv(env));
    for (const hole of shellHoles(value)) {
      if (!hole.report) {continue;}
      findings.push({ file, line: lineOf(call), ruleId: 'SAST-CMDI-001', shellContext: hole.context });
    }
  }
}

function noteArgv(
  call: TSESTree.CallExpression,
  env: ReadonlyMap<string, Binding>,
  file: string,
  findings: ShellFinding[],
): void {
  const arg = call.arguments[1];
  if (arg === undefined || arg.type !== 'ArrayExpression') {return;}
  let separated = false;
  for (const element of arg.elements) {
    if (element === null || element.type === 'SpreadElement') {continue;}
    if (element.type === 'Literal' && element.value === '--') {separated = true; continue;}
    const binding = bindingOf(element, env);
    if (!binding.tainted || separated || !allowsDash(binding.charClass)) {continue;}
    findings.push({ file, line: lineOf(call), ruleId: 'SAST-CMDI-001', shellContext: 'option' });
    return;
  }
}

function shellHoles(value: AbstractString): { context: ShellContext; report: boolean }[] {
  const holes: { context: ShellContext; report: boolean }[] = [];
  let state: 'code' | 'sq' | 'dq' = 'code';
  let preceding = '';
  for (const seg of value.segments) {
    if (seg.kind === 'literal') {
      const stepped = stepLiteral(seg.text, state, preceding);
      state = stepped.state;
      preceding = stepped.preceding;
      continue;
    }
    const noted = noteShellHole(seg, state, preceding);
    if (noted !== null) {holes.push(noted);}
    preceding += ' ';
  }
  return holes;
}

function stepLiteral(text: string, state: 'code' | 'sq' | 'dq', preceding: string): { state: 'code' | 'sq' | 'dq'; preceding: string } {
  let next = state;
  let prefix = preceding;
  for (const ch of text) {
    const stepped = stepChar(next, ch);
    next = stepped.state;
    if (stepped.keep) {prefix += ch;}
  }
  return { state: next, preceding: prefix };
}

function stepChar(state: 'code' | 'sq' | 'dq', ch: string): { state: 'code' | 'sq' | 'dq'; keep: boolean } {
  if (state === 'code' && ch === "'") {return { state: 'sq', keep: false };}
  if (state === 'sq' && ch === "'") {return { state: 'code', keep: false };}
  if (state === 'code' && ch === '"') {return { state: 'dq', keep: false };}
  if (state === 'dq' && ch === '"') {return { state: 'code', keep: false };}
  if (state === 'code') {return { state, keep: true };}
  return { state, keep: false };
}

function noteShellHole(seg: Segment, state: 'code' | 'sq' | 'dq', preceding: string): { context: ShellContext; report: boolean } | null {
  const charClass: CharClass | 'any' = seg.kind === 'tainted' ? seg.charClass : 'any';
  if (labelsOf({ segments: [seg] }).length === 0 && seg.kind !== 'unknown') {return null;}
  if (state === 'sq') {return { context: 'single', report: !excludesQuote(charClass) };}
  if (state === 'dq') {return { context: 'double', report: true };}
  if (/(?:^|\s)-$/.test(preceding) && allowsDash(charClass)) {return { context: 'option', report: true };}
  return { context: 'bare', report: true };
}

function bindingOf(node: TSESTree.Node, env: ReadonlyMap<string, Binding>): Binding {
  const current = stripNode(node);
  if (isRequestSource(current)) {return { tainted: true, charClass: 'any' };}
  if (current.type === 'Identifier') {return env.get(current.name) ?? { tainted: false, charClass: 'any' };}
  if (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'Identifier' && (callee.name === 'Number' || callee.name === 'parseInt')) {
      const arg = current.arguments[0];
      const inner = arg === undefined || arg.type === 'SpreadElement' ? { tainted: false, charClass: 'numeric' as const } : bindingOf(arg, env);
      return { tainted: inner.tainted, charClass: 'numeric' };
    }
  }
  const value = abstractExpression(current, stringEnv(env));
  const labels = labelsOf(value);
  const seg = value.segments.find((item): item is Extract<Segment, { kind: 'tainted' }> => item.kind === 'tainted');
  return { tainted: labels.length > 0, charClass: seg?.charClass ?? 'any' };
}

function stringEnv(env: ReadonlyMap<string, Binding>): Map<string, AbstractString> {
  const out = new Map<string, AbstractString>();
  for (const [name, binding] of env) {
    if (binding.tainted) {out.set(name, { segments: [{ kind: 'tainted', labels: ['cmdi'], charClass: binding.charClass }] });}
  }
  return out;
}

function calleeName(node: TSESTree.Node): string | null {
  const current = stripNode(node);
  if (current.type === 'Identifier') {return current.name;}
  if (current.type === 'MemberExpression') {return propName(current);}
  return null;
}

function shellTrue(call: TSESTree.CallExpression): boolean {
  const arg = call.arguments[2] ?? call.arguments[1];
  if (arg === undefined || arg.type !== 'ObjectExpression') {return false;}
  return arg.properties.some((prop) => prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === 'shell' && prop.value.type === 'Literal' && prop.value.value === true);
}

function allowsDash(charClass: CharClass): boolean {
  return charClass === 'any' || charClass === 'numeric';
}

function excludesQuote(charClass: CharClass): boolean {
  return charClass === 'no-quote' || charClass === 'digits' || charClass === 'numeric' || charClass === 'letters' || charClass === 'no-dash';
}
