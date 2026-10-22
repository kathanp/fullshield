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
  const walk = (stmts: readonly TSESTree.Statement[], env: Map<string, Binding>, params: ReadonlySet<string>): void => {
    for (const stmt of stmts) {
      if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {
        const names = new Set(stmt.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : [])));
        const next = new Map(env);
        for (const name of names) {next.set(name, { tainted: true, charClass: 'any' });}
        walk(stmt.body.body, next, names);
        continue;
      }
      if (stmt.type === 'BlockStatement') {walk(stmt.body, env, params); continue;}
      if (stmt.type === 'IfStatement') {
        walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env, params);
        if (stmt.alternate !== null) {walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate], env, params);}
        continue;
      }
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations) {
          if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, bindingOf(decl.init, env));}
        }
        continue;
      }
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
        noteCall(stmt.expression, env, file, findings);
      }
    }
  };
  walk(program.body, new Map(), new Set());
  return { findings };
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
      for (const ch of seg.text) {
        if (state === 'code' && ch === "'") {state = 'sq';}
        else if (state === 'sq' && ch === "'") {state = 'code';}
        else if (state === 'code' && ch === '"') {state = 'dq';}
        else if (state === 'dq' && ch === '"') {state = 'code';}
        else if (state === 'code') {preceding += ch;}
      }
      continue;
    }
    const charClass: CharClass | 'any' = seg.kind === 'tainted' ? seg.charClass : 'any';
    if (labelsOf({ segments: [seg] }).length === 0 && seg.kind !== 'unknown') {continue;}
    if (state === 'sq') {holes.push({ context: 'single', report: !excludesQuote(charClass) });}
    else if (state === 'dq') {holes.push({ context: 'double', report: true });}
    else if (/(?:^|\s)-$/.test(preceding) && allowsDash(charClass)) {holes.push({ context: 'option', report: true });}
    else {holes.push({ context: 'bare', report: true });}
    preceding += ' ';
  }
  return holes;
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
