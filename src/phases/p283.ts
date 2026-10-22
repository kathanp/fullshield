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
  const walk = (stmts: readonly TSESTree.Statement[], env: Map<string, PathValue>, guarded: boolean): void => {
    for (const stmt of stmts) {
      if (stmt.type === 'FunctionDeclaration') {walk(stmt.body.body, new Map(env), false); continue;}
      if (stmt.type === 'BlockStatement') {walk(stmt.body, env, guarded); continue;}
      if (stmt.type === 'IfStatement') {
        const guard = isPrefixGuard(stmt.test);
        walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env, guarded || guard);
        if (stmt.alternate !== null) {walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate], env, guarded);}
        continue;
      }
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations) {
          if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, evalPath(decl.init, env, windows));}
        }
        continue;
      }
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'AssignmentExpression' && stmt.expression.left.type === 'Identifier') {
        env.set(stmt.expression.left.name, evalPath(stmt.expression.right, env, windows));
        continue;
      }
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
        noteSink(stmt.expression, env, windows, guarded, file, findings);
      }
    }
  };
  walk(program.body, new Map(), false);
  return { findings };
}

function noteSink(
  call: TSESTree.CallExpression,
  env: ReadonlyMap<string, PathValue>,
  windows: boolean,
  guarded: boolean,
  file: string,
  findings: PathFinding[],
): void {
  const name = sinkName(call.callee);
  if (name === null) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = evalPath(arg, env, windows);
  if (guarded || !value.traversal) {return;}
  findings.push({ file, line: lineOf(call), traversal: true });
}

function evalPath(node: TSESTree.Node, env: ReadonlyMap<string, PathValue>, windows: boolean): PathValue {
  const current = stripNode(node);
  if (isRequestSource(current)) {return DANGER;}
  if (current.type === 'Identifier') {return env.get(current.name) ?? SAFE;}
  if (current.type === 'Literal') {
    if (windows && typeof current.value === 'string' && /^[A-Za-z]:/.test(current.value)) {
      return { traversal: false, absolute: true };
    }
    return SAFE;
  }
  if (current.type === 'TemplateLiteral') {
    const parts = current.expressions.map((expr) => evalPath(expr, env, windows));
    return joinValues(parts);
  }
  if (current.type === 'BinaryExpression' && current.operator === '+') {
    return joinValues([evalPath(current.left, env, windows), evalPath(current.right, env, windows)]);
  }
  if (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    const name = callee.type === 'MemberExpression' ? propName(callee) : callee.type === 'Identifier' ? callee.name : null;
    const args = current.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [evalPath(arg, env, windows)]));
    if (name === 'basename') {return SAFE;}
    if (name === 'join' || name === 'normalize') {return { traversal: args.some((arg) => arg.traversal), absolute: args[0]?.absolute ?? false };}
    if (name === 'resolve') {
      const tainted = args.some((arg) => arg.traversal || arg.absolute);
      const drops = args.slice(1).some((arg) => arg.absolute);
      return { traversal: tainted, absolute: drops || (args[0]?.absolute ?? false) };
    }
    if (name === 'readFile' || name === 'readFileSync' || name === 'sendFile') {return args[0] ?? SAFE;}
  }
  return SAFE;
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
