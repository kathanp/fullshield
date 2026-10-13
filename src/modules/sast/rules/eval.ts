import { calleeName, isLiteralExpr } from '../ast.js';
import type { SastRule } from '../types.js';

const VM_METHODS = new Set(['runInNewContext', 'runInContext', 'runInThisContext']);

export const evalRule: SastRule = {
  meta: {
    id: 'SAST-EVAL-001',
    title: 'Dynamic code execution with a non-literal',
    severity: 'high',
    cwe: 'CWE-95',
    docs: 'https://cwe.mitre.org/data/definitions/95.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        // Bare `eval(...)` and library wrappers (`mathjs.eval(...)`) are both sinks.
        const isEval = name === 'eval';
        const isVm = name !== undefined && VM_METHODS.has(name);
        if (!isEval && !isVm) return;
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement' || isLiteralExpr(arg)) return;
        ctx.report({
          node,
          message: 'eval / vm.runInNewContext is called with a non-literal argument.',
        });
      },
      NewExpression(node) {
        if (node.type !== 'NewExpression') return;
        if (node.callee.type !== 'Identifier' || node.callee.name !== 'Function') return;
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement' || isLiteralExpr(arg)) return;
        ctx.report({
          node,
          message: 'new Function is called with a non-literal argument.',
        });
      },
    };
  },
};
