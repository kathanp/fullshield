import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PATHCTX';

export interface PathFinding {
  file: string;
  line: number;
  traversal: boolean;
}

interface PathValue {
  traversal: boolean;
  absolute: boolean;
}

const DANGER: PathValue = { traversal: true, absolute: true };
const SAFE: PathValue = { traversal: false, absolute: false };

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function projectTargetsWindows(pkg: { engines?: { os?: string }; dependencies?: Readonly<Record<string, string>> }): boolean {
  if (pkg.engines?.os?.includes('win32') === true) {return true;}
  return pkg.dependencies !== undefined && Object.prototype.hasOwnProperty.call(pkg.dependencies, 'electron');
}

export function analyzePath(source: string, options?: { file?: string; windows?: boolean }): { findings: PathFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const windows = options?.windows ?? false;
  const findings: PathFinding[] = [];
  const bag: PathWalk = { windows, file, findings, walk: () => undefined };
  bag.walk = (stmts, env, guarded) => {
    for (const stmt of stmts) {walkPath(stmt, env, guarded, bag);}
  };
  bag.walk(program.body, new Map(), false);
  return { findings };
}

interface PathWalk {
  windows: boolean;
  file: string;
  findings: PathFinding[];
  walk: (stmts: readonly TSESTree.Statement[], env: Map<string, PathValue>, guarded: boolean) => void;
}

function walkPath(stmt: TSESTree.Statement, env: Map<string, PathValue>, guarded: boolean, bag: PathWalk): void {
  if (stmt.type === 'FunctionDeclaration') {bag.walk(stmt.body.body, new Map(env), false); return;}
  if (stmt.type === 'BlockStatement') {bag.walk(stmt.body, env, guarded); return;}
  if (stmt.type === 'IfStatement') {walkPathIf(stmt, env, guarded, bag); return;}
  if (stmt.type === 'VariableDeclaration') {bindPathVars(stmt, env, bag.windows); return;}
  walkPathExpr(stmt, env, guarded, bag);
}

function walkPathIf(stmt: TSESTree.IfStatement, env: Map<string, PathValue>, guarded: boolean, bag: PathWalk): void {
  const guard = isPrefixGuard(stmt.test);
  bag.walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env, guarded || guard);
  if (stmt.alternate !== null) {bag.walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate], env, guarded);}
}

function bindPathVars(stmt: TSESTree.VariableDeclaration, env: Map<string, PathValue>, windows: boolean): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, evalPath(decl.init, env, windows));}
  }
}

function walkPathExpr(stmt: TSESTree.Statement, env: Map<string, PathValue>, guarded: boolean, bag: PathWalk): void {
  if (stmt.type !== 'ExpressionStatement') {return;}
  if (stmt.expression.type === 'AssignmentExpression' && stmt.expression.left.type === 'Identifier') {
    env.set(stmt.expression.left.name, evalPath(stmt.expression.right, env, bag.windows));
    return;
  }
  if (stmt.expression.type === 'CallExpression') {noteSink(stmt.expression, env, guarded, bag);}
}

function noteSink(call: TSESTree.CallExpression, env: ReadonlyMap<string, PathValue>, guarded: boolean, bag: PathWalk): void {
  const name = sinkName(call.callee);
  if (name === null) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = evalPath(arg, env, bag.windows);
  if (guarded || !value.traversal) {return;}
  bag.findings.push({ file: bag.file, line: lineOf(call), traversal: true });
}

function evalPath(node: TSESTree.Node, env: ReadonlyMap<string, PathValue>, windows: boolean): PathValue {
  const current = stripNode(node);
  if (isRequestSource(current)) {return DANGER;}
  if (current.type === 'Identifier') {return env.get(current.name) ?? SAFE;}
  if (current.type === 'Literal') {return evalPathLiteral(current, windows);}
  if (current.type === 'TemplateLiteral') {return joinValues(current.expressions.map((expr) => evalPath(expr, env, windows)));}
  if (current.type === 'BinaryExpression' && current.operator === '+') {
    return joinValues([evalPath(current.left, env, windows), evalPath(current.right, env, windows)]);
  }
  if (current.type === 'CallExpression') {return evalPathCall(current, env, windows);}
  return SAFE;
}

function evalPathLiteral(current: TSESTree.Literal, windows: boolean): PathValue {
  if (windows && typeof current.value === 'string' && /^[A-Za-z]:/.test(current.value)) {
    return { traversal: false, absolute: true };
  }
  return SAFE;
}

function evalPathCall(current: TSESTree.CallExpression, env: ReadonlyMap<string, PathValue>, windows: boolean): PathValue {
  const callee = stripNode(current.callee);
  const name = pathCallee(callee);
  const args = current.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [evalPath(arg, env, windows)]));
  if (name === 'basename') {return SAFE;}
  if (name === 'join' || name === 'normalize') {return joinPath(args);}
  if (name === 'resolve') {return resolvePath(args);}
  if (name === 'readFile' || name === 'readFileSync' || name === 'sendFile') {return args[0] ?? SAFE;}
  return SAFE;
}

function pathCallee(callee: TSESTree.Node): string | null {
  if (callee.type === 'MemberExpression') {return propName(callee);}
  if (callee.type === 'Identifier') {return callee.name;}
  return null;
}

function joinPath(args: readonly PathValue[]): PathValue {
  return { traversal: args.some((arg) => arg.traversal), absolute: args[0]?.absolute ?? false };
}

function resolvePath(args: readonly PathValue[]): PathValue {
  const tainted = args.some((arg) => arg.traversal || arg.absolute);
  const drops = args.slice(1).some((arg) => arg.absolute);
  return { traversal: tainted, absolute: drops || (args[0]?.absolute ?? false) };
}

function joinValues(parts: readonly PathValue[]): PathValue {
  return {
    traversal: parts.some((part) => part.traversal),
    absolute: parts.some((part) => part.absolute),
  };
}

function sinkName(node: TSESTree.Node): string | null {
  const current = stripNode(node);
  const name = current.type === 'Identifier' ? current.name : current.type === 'MemberExpression' ? propName(current) : null;
  if (name === 'readFile' || name === 'readFileSync' || name === 'sendFile' || name === 'open') {return name;}
  return null;
}

function isPrefixGuard(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  if (current.type !== 'CallExpression' || current.callee.type !== 'MemberExpression' || propName(current.callee) !== 'startsWith') {
    return false;
  }
  const arg = current.arguments[0];
  if (arg === undefined || arg.type !== 'BinaryExpression' || arg.operator !== '+') {return false;}
  return usesSep(arg.right);
}

function usesSep(node: TSESTree.Node): boolean {
  if (node.type === 'MemberExpression' && propName(node) === 'sep') {return true;}
  if (node.type === 'Literal' && (node.value === '/' || node.value === '\\')) {return true;}
  if (node.type === 'BinaryExpression') {return usesSep(node.left) || usesSep(node.right);}
  return false;
}
