import { calleeName } from '../ast.js';
import type { SastRule } from '../types.js';

const MERGE_NAMES = new Set(['merge', 'defaultsDeep', 'deepMerge', 'deepExtend', 'deepAssign']);

export const protoRule: SastRule = {
  meta: {
    id: 'SAST-PROTO-001',
    title: 'Prototype pollution via recursive merge',
    severity: 'high',
    cwe: 'CWE-1321',
    docs: 'https://cwe.mitre.org/data/definitions/1321.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name === undefined || !MERGE_NAMES.has(name)) return;
        const taintedArg = node.arguments.some(
          (arg) => arg.type !== 'SpreadElement' && ctx.isTainted(arg),
        );
        if (!taintedArg) return;
        // A real guard compares a key against '__proto__'. A comment mentioning
        // the identifier must not suppress the finding.
        if (/===\s*['"]__proto__['"]|['"]__proto__['"]\s*===/.test(ctx.source)) return;
        ctx.report({
          node,
          message: 'Recursive merge/assign of a tainted object without a __proto__ guard.',
        });
      },
    };
  },
};
