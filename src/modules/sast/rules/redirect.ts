import { calleeName } from '../ast.js';
import type { SastRule } from '../types.js';

export const redirectRule: SastRule = {
  meta: {
    id: 'SAST-REDIRECT-001',
    title: 'Open redirect',
    severity: 'high',
    cwe: 'CWE-601',
    docs: 'https://cwe.mitre.org/data/definitions/601.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        if (calleeName(node) !== 'redirect') return;
        const target = node.arguments[0];
        if (target === undefined || target.type === 'SpreadElement') return;
        if (!ctx.isTainted(target) || ctx.isSanitizedFor(target, 'url')) return;
        ctx.report({
          node,
          message: 'Tainted input is passed to res.redirect.',
        });
      },
    };
  },
};
