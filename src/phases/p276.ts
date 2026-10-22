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
  const walk = (stmts: readonly TSESTree.Statement[], env: Map<string, Info>): void => {
    for (const stmt of stmts) {exec(stmt, env, gens, findings, file, new Set());}
  };
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration') {walk(stmt.body.body, new Map());}
    else {exec(stmt, new Map(), gens, findings, file, new Set());}
  }
  return { findings };
}

function exec(
  stmt: TSESTree.Statement,
  env: Map<string, Info>,
  gens: ReadonlyMap<string, GenFn>,
  findings: GeneratorFinding[],
  file: string,
  stack: Set<string>,
): void {
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, evalExpr(decl.init, env, gens, stack));}
    }
    return;
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
      env.set(expr.left.name, evalExpr(expr.right, env, gens, stack));
    }
    if (expr.type === 'CallExpression') {noteSink(expr, env, gens, findings, file, stack);}
    return;
  }
  if (stmt.type === 'ForOfStatement') {
    const info = iterInfo(stmt.right, env, gens, stack);
    if (stmt.left.type === 'VariableDeclaration') {
      const decl = stmt.left.declarations[0];
      if (decl !== undefined && decl.id.type === 'Identifier') {env.set(decl.id.name, info);}
    }
    const body = stmt.body.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
    for (const inner of body) {exec(inner, env, gens, findings, file, stack);}
    return;
  }
  if (stmt.type === 'BlockStatement') {
    for (const inner of stmt.body) {exec(inner, env, gens, findings, file, stack);}
  }
  if (stmt.type === 'IfStatement') {
    exec(stmt.consequent, env, gens, findings, file, stack);
    if (stmt.alternate !== null) {exec(stmt.alternate, env, gens, findings, file, stack);}
  }
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
  const visit = (stmts: readonly TSESTree.Statement[]): void => {
    for (const stmt of stmts) {
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'YieldExpression' && stmt.expression.argument !== null) {
        if (stmt.expression.delegate && stmt.expression.argument.type === 'CallExpression' && stmt.expression.argument.callee.type === 'Identifier') {
          yields.push(...runGenerator(stmt.expression.argument.callee.name, gens, stack));
        } else {
          yields.push(evalExpr(stmt.expression.argument, env, gens, stack));
        }
      } else if (stmt.type === 'BlockStatement') {visit(stmt.body);}
      else if (stmt.type === 'IfStatement') {
        if (stmt.consequent.type === 'BlockStatement') {visit(stmt.consequent.body);}
        else if (stmt.consequent.type === 'ExpressionStatement') {visit([stmt.consequent]);}
        if (stmt.alternate !== null && stmt.alternate.type === 'BlockStatement') {visit(stmt.alternate.body);}
      } else if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {
        const body = stmt.body.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
        visit(body);
      }
    }
  };
  visit(fn.body.body);
  stack.delete(name);
  return yields;
}

function noteSink(
  call: TSESTree.CallExpression,
  env: Map<string, Info>,
  gens: ReadonlyMap<string, GenFn>,
  findings: GeneratorFinding[],
  file: string,
  stack: Set<string>,
): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const info = evalExpr(arg, env, gens, stack);
  if (!info.tainted) {return;}
  const finding: GeneratorFinding = { file, line: lineOf(call), labels: ['sqli'] };
  if (info.identifier) {finding.sqlContext = 'identifier';}
  findings.push(finding);
}

function evalExpr(node: TSESTree.Node, env: ReadonlyMap<string, Info>, gens: ReadonlyMap<string, GenFn>, stack: Set<string>): Info {
  const current = stripNode(node);
  if (isRequestSource(current)) {return { tainted: true, identifier: false };}
  if (current.type === 'Identifier') {return env.get(current.name) ?? EMPTY;}
  if (current.type === 'Literal') {return EMPTY;}
  if (current.type === 'BinaryExpression') {
    return join(evalExpr(current.left, env, gens, stack), evalExpr(current.right, env, gens, stack));
  }
  if (current.type === 'TemplateLiteral') {
    return current.expressions.reduce<Info>((acc, expr) => join(acc, evalExpr(expr, env, gens, stack)), EMPTY);
  }
  if (current.type === 'MemberExpression') {
    const info = evalExpr(current.object, env, gens, stack);
    if (current.computed && current.property.type === 'Literal') {return info;}
    return info;
  }
  if (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && callee.object.name === 'Object') {
      const method = propName(callee);
      const arg = current.arguments[0];
      if ((method === 'keys' || method === 'values' || method === 'entries') && arg !== undefined && arg.type !== 'SpreadElement') {
        const info = evalExpr(arg, env, gens, stack);
        if (info.tainted || isRequestSource(arg)) {return { tainted: true, identifier: method === 'keys' };}
      }
    }
  }
  return EMPTY;
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
