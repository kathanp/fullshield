import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GENERATORS';

export interface GeneratorFinding {
  file: string;
  line: number;
  labels: string[];
  sqlContext?: 'identifier';
}

interface Info {
  tainted: boolean;
  identifier: boolean;
}

interface GenFn {
  params: string[];
  body: TSESTree.BlockStatement;
}

const EMPTY: Info = { tainted: false, identifier: false };

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeGenerators(source: string, options?: { file?: string }): { findings: GeneratorFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const gens = new Map<string, GenFn>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.generator && stmt.id !== null) {
      gens.set(stmt.id.name, { params: names(stmt.params), body: stmt.body });
    }
  }
  const findings: GeneratorFinding[] = [];
  for (const stmt of program.body) {execTop(stmt, gens, findings, file);}
  return { findings };
}

interface GenState {
  env: Map<string, Info>;
  gens: ReadonlyMap<string, GenFn>;
  findings: GeneratorFinding[];
  file: string;
  stack: Set<string>;
}

function execTop(stmt: TSESTree.Statement, gens: ReadonlyMap<string, GenFn>, findings: GeneratorFinding[], file: string): void {
  if (stmt.type === 'FunctionDeclaration') {
    for (const inner of stmt.body.body) {exec(inner, freshState(new Map(), gens, findings, file));}
    return;
  }
  exec(stmt, freshState(new Map(), gens, findings, file));
}

function freshState(env: Map<string, Info>, gens: ReadonlyMap<string, GenFn>, findings: GeneratorFinding[], file: string): GenState {
  return { env, gens, findings, file, stack: new Set() };
}

function exec(stmt: TSESTree.Statement, state: GenState): void {
  if (stmt.type === 'VariableDeclaration') {execVars(stmt, state); return;}
  if (stmt.type === 'ExpressionStatement') {execExpr(stmt, state); return;}
  if (stmt.type === 'ForOfStatement') {execForOf(stmt, state); return;}
  if (stmt.type === 'BlockStatement') {execBlock(stmt.body, state);}
  if (stmt.type === 'IfStatement') {execIf(stmt, state);}
}

function execVars(stmt: TSESTree.VariableDeclaration, state: GenState): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {
      state.env.set(decl.id.name, evalExpr(decl.init, state.env, state.gens, state.stack));
    }
  }
}

function execExpr(stmt: TSESTree.ExpressionStatement, state: GenState): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    state.env.set(expr.left.name, evalExpr(expr.right, state.env, state.gens, state.stack));
  }
  if (expr.type === 'CallExpression') {noteSink(expr, state);}
}

function execForOf(stmt: TSESTree.ForOfStatement, state: GenState): void {
  const info = iterInfo(stmt.right, state.env, state.gens, state.stack);
  if (stmt.left.type === 'VariableDeclaration') {bindForOf(stmt.left, info, state.env);}
  const body = stmt.body.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
  execBlock(body, state);
}

function bindForOf(left: TSESTree.VariableDeclaration, info: Info, env: Map<string, Info>): void {
  const decl = left.declarations[0];
  if (decl !== undefined && decl.id.type === 'Identifier') {env.set(decl.id.name, info);}
}

function execBlock(body: readonly TSESTree.Statement[], state: GenState): void {
  for (const inner of body) {exec(inner, state);}
}

function execIf(stmt: TSESTree.IfStatement, state: GenState): void {
  exec(stmt.consequent, state);
  if (stmt.alternate !== null) {exec(stmt.alternate, state);}
}

function iterInfo(node: TSESTree.Node, env: Map<string, Info>, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info {
  const current = stripNode(node);
  if (current.type === 'CallExpression' && current.callee.type === 'Identifier') {
    const yields = runGenerator(current.callee.name, gens, stack);
    return {
      tainted: yields.some((item) => item.tainted),
      identifier: yields.some((item) => item.identifier),
    };
  }
  return evalExpr(current, env, gens, stack);
}

function runGenerator(name: string, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info[] {
  if (stack.has(name)) {return [];}
  const fn = gens.get(name);
  if (fn === undefined) {return [];}
  stack.add(name);
  const yields: Info[] = [];
  const env = new Map<string, Info>();
  const frame: GenFrame = { env, gens, stack, yields, visit: () => undefined };
  frame.visit = (stmts) => {
    for (const stmt of stmts) {visitGenStmt(stmt, frame);}
  };
  frame.visit(fn.body.body);
  stack.delete(name);
  return yields;
}

interface GenFrame {
  env: Map<string, Info>;
  gens: ReadonlyMap<string, GenFn>;
  stack: Set<string>;
  yields: Info[];
  visit: (stmts: readonly TSESTree.Statement[]) => void;
}

function visitGenStmt(stmt: TSESTree.Statement, frame: GenFrame): void {
  if (isYieldStmt(stmt)) {frame.yields.push(...yieldInfos(stmt.expression, frame.env, frame.gens, frame.stack)); return;}
  if (stmt.type === 'BlockStatement') {frame.visit(stmt.body); return;}
  if (stmt.type === 'IfStatement') {visitIf(stmt, frame.visit); return;}
  if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {
    frame.visit(stmt.body.type === 'BlockStatement' ? stmt.body.body : [stmt.body]);
  }
}

function isYieldStmt(stmt: TSESTree.Statement): stmt is TSESTree.ExpressionStatement & { expression: TSESTree.YieldExpression & { argument: TSESTree.Expression } } {
  return stmt.type === 'ExpressionStatement' && stmt.expression.type === 'YieldExpression' && stmt.expression.argument !== null;
}

function yieldInfos(
  expr: TSESTree.YieldExpression & { argument: TSESTree.Expression },
  env: Map<string, Info>,
  gens: ReadonlyMap<string, GenFn>,
  stack: Set<string>,
): Info[] {
  if (expr.delegate && expr.argument.type === 'CallExpression' && expr.argument.callee.type === 'Identifier') {
    return runGenerator(expr.argument.callee.name, gens, stack);
  }
  return [evalExpr(expr.argument, env, gens, stack)];
}

function visitIf(stmt: TSESTree.IfStatement, visit: (stmts: readonly TSESTree.Statement[]) => void): void {
  if (stmt.consequent.type === 'BlockStatement') {visit(stmt.consequent.body);}
  else if (stmt.consequent.type === 'ExpressionStatement') {visit([stmt.consequent]);}
  if (stmt.alternate !== null && stmt.alternate.type === 'BlockStatement') {visit(stmt.alternate.body);}
}

function noteSink(call: TSESTree.CallExpression, state: GenState): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const info = evalExpr(arg, state.env, state.gens, state.stack);
  if (!info.tainted) {return;}
  const finding: GeneratorFinding = { file: state.file, line: lineOf(call), labels: ['sqli'] };
  if (info.identifier) {finding.sqlContext = 'identifier';}
  state.findings.push(finding);
}

function evalExpr(node: TSESTree.Node, env: ReadonlyMap<string, Info>, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info {
  const current = stripNode(node);
  if (isRequestSource(current)) {return { tainted: true, identifier: false };}
  if (current.type === 'Identifier') {return env.get(current.name) ?? EMPTY;}
  if (current.type === 'Literal') {return EMPTY;}
  if (current.type === 'BinaryExpression') {return join(evalExpr(current.left, env, gens, stack), evalExpr(current.right, env, gens, stack));}
  if (current.type === 'TemplateLiteral') {return evalTemplate(current, env, gens, stack);}
  if (current.type === 'MemberExpression') {return evalExpr(current.object, env, gens, stack);}
  if (current.type === 'CallExpression') {return evalObjectCall(current, env, gens, stack);}
  return EMPTY;
}

function evalTemplate(current: TSESTree.TemplateLiteral, env: ReadonlyMap<string, Info>, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info {
  return current.expressions.reduce<Info>((acc, expr) => join(acc, evalExpr(expr, env, gens, stack)), EMPTY);
}

function evalObjectCall(current: TSESTree.CallExpression, env: ReadonlyMap<string, Info>, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info {
  const callee = stripNode(current.callee);
  if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier' || callee.object.name !== 'Object') {return EMPTY;}
  const method = propName(callee);
  const arg = current.arguments[0];
  if (!isObjectMethod(method) || arg === undefined || arg.type === 'SpreadElement') {return EMPTY;}
  const info = evalExpr(arg, env, gens, stack);
  if (info.tainted || isRequestSource(arg)) {return { tainted: true, identifier: method === 'keys' };}
  return EMPTY;
}

function isObjectMethod(method: string | null): method is 'keys' | 'values' | 'entries' {
  return method === 'keys' || method === 'values' || method === 'entries';
}

function join(left: Info, right: Info): Info {
  return { tainted: left.tainted || right.tainted, identifier: left.identifier || right.identifier };
}

function names(params: TSESTree.Parameter[]): string[] {
  return params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : []));
}

export function generatorYieldCount(source: string): number {
  if (!enabled()) {return 0;}
  const program = parseProgram(source);
  if (program === null) {return 0;}
  let count = 0;
  walkAst(program, (node) => {
    if (node.type === 'YieldExpression') {count += 1;}
  });
  return count;
}
