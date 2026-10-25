import { calleeName, isLiteralExpr, literalString } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

const VM_METHODS = new Set(['runInNewContext', 'runInContext', 'runInThisContext']);
const EVAL_LIB = String.raw`(?:mathjs|expr-eval|vm2)`;

function boundNames(source: string): Set<string> {
  const names = new Set<string>();
  const patterns = [
    new RegExp(String.raw`import\s+\*\s+as\s+(\w+)\s+from\s+['"]${EVAL_LIB}['"]`, 'g'),
    new RegExp(String.raw`import\s+(\w+)\s+from\s+['"]${EVAL_LIB}['"]`, 'g'),
    new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"]${EVAL_LIB}['"]\s*\)`, 'g'),
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1] !== undefined) {names.add(match[1]);}
    }
  }
  return names;
}

function importsName(source: string, name: string, lib: string): boolean {
  const imported = new RegExp(String.raw`import\s*\{[^}]*\b${name}\b[^}]*\}\s*from\s*['"]${lib}['"]`);
  const required = new RegExp(String.raw`(?:const|let|var)\s*\{[^}]*\b${name}\b[^}]*\}\s*=\s*require\(\s*['"]${lib}['"]\s*\)`);
  return imported.test(source) || required.test(source);
}

function libraryEvaluate(node: AstNode, source: string, locals: Set<string>): boolean {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'evaluate') {return false;}
  if (node.callee.type === 'Identifier') {return importsName(source, 'evaluate', EVAL_LIB);}
  if (node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  if (object.type === 'Identifier' && locals.has(object.name)) {return true;}
  return object.type === 'NewExpression' && calleeName(object) === 'Parser' && importsName(source, 'Parser', 'expr-eval');
}

function vm2Dynamic(node: AstNode, source: string): boolean {
  if (node.type !== 'NewExpression') {return false;}
  if (!/['"]vm2['"]/.test(source)) {return false;}
  const name = calleeName(node);
  if (name !== 'VM' && name !== 'NodeVM') {return false;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return false;}
  if (arg.type !== 'ObjectExpression') {return !isLiteralExpr(arg);}
  for (const prop of arg.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if ((key === 'code' || key === 'eval') && !isLiteralExpr(prop.value)) {return true;}
  }
  return false;
}

export const evalRule: SastRule = {
  meta: {
    id: 'SAST-EVAL-001',
    title: 'Dynamic code execution with a non-literal',
    severity: 'high',
    cwe: 'CWE-95',
    docs: 'https://cwe.mitre.org/data/definitions/95.html',
  },
  create(ctx) {
    const locals = boundNames(ctx.source);
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        // Bare `eval(...)` and library wrappers (`mathjs.eval(...)`) are both sinks.
        const isEval = name === 'eval';
        const isVm = name !== undefined && VM_METHODS.has(name);
        const isLib = libraryEvaluate(node, ctx.source, locals);
        if (!isEval && !isVm && !isLib) {return;}
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement' || isLiteralExpr(arg)) {return;}
        ctx.report({
          node,
          message: 'eval / vm.runInNewContext is called with a non-literal argument.',
        });
      },
      NewExpression(node) {
        if (node.type !== 'NewExpression') {return;}
        if (vm2Dynamic(node, ctx.source)) {
          ctx.report({
            node,
            message: 'vm2 VM is constructed with a non-literal code argument.',
          });
          return;
        }
        if (node.callee.type !== 'Identifier' || node.callee.name !== 'Function') {return;}
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement' || isLiteralExpr(arg)) {return;}
        ctx.report({
          node,
          message: 'new Function is called with a non-literal argument.',
        });
      },
    };
  },
};
