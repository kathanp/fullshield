import { calleeName, literalString, walk } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

function containsHtml(node: AstNode): boolean {
  let found = false;
  walk(node, (child) => {
    const lit = literalString(child);
    if (lit !== undefined && /<[^>]+>/.test(lit)) found = true;
    if (child.type === 'TemplateLiteral') {
      for (const q of child.quasis) {
        if (/<[^>]+>/.test(q.value.cooked ?? q.value.raw)) found = true;
      }
    }
  });
  return found;
}

export const xssRule: SastRule = {
  meta: {
    id: 'SAST-XSS-001',
    title: 'Reflected XSS via HTML response',
    severity: 'high',
    cwe: 'CWE-79',
    docs: 'https://cwe.mitre.org/data/definitions/79.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name !== 'send' && name !== 'write') return;
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement') return;
        if (!ctx.isTainted(arg)) return;
        if (!containsHtml(arg) && !/\{\{\{/.test(ctx.source) && !/<%-/.test(ctx.source)) return;
        ctx.report({
          node,
          message: 'Tainted input is interpolated into an HTML response.',
        });
      },
    };
  },
};
