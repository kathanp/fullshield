import { calleeName, literalString } from '../ast.js';
import { sastGapsEnabled } from '../experimental.js';
import type { AstNode, SastRule } from '../types.js';

const MONGO_SINKS = new Set([
  'find',
  'findOne',
  'findOneAndUpdate',
  'update',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'remove',
  'aggregate',
]);

function objectHasTaintedWhere(node: AstNode, isTainted: (n: AstNode) => boolean): boolean {
  if (node.type !== 'ObjectExpression') return false;
  for (const prop of node.properties) {
    if (prop.type !== 'Property') continue;
    const key =
      prop.key.type === 'Identifier'
        ? prop.key.name
        : prop.key.type === 'Literal'
          ? String(prop.key.value)
          : literalString(prop.key);
    if (key === '$where' && isTainted(prop.value)) return true;
  }
  return false;
}

export const nosqliRule: SastRule = {
  meta: {
    id: 'SAST-NOSQLI-001',
    title: 'NoSQL injection via raw request object filter',
    severity: 'high',
    cwe: 'CWE-943',
    docs: 'https://cwe.mitre.org/data/definitions/943.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (sastGapsEnabled() && name === '$where') {
          const expr = node.arguments[0];
          if (expr !== undefined && expr.type !== 'SpreadElement' && ctx.isTainted(expr)) {
            ctx.report({
              node,
              message: 'Tainted input is passed to mongoose $where (server-side JS).',
            });
          }
          return;
        }
        if (name === undefined || !MONGO_SINKS.has(name)) return;
        const filter = node.arguments[0];
        if (filter === undefined || filter.type === 'SpreadElement') return;
        if (ctx.isRequestObject(filter)) {
          ctx.report({
            node,
            message: 'req.body/req.query is passed directly into a Mongo-style filter.',
          });
          return;
        }
        if (sastGapsEnabled() && objectHasTaintedWhere(filter, (n) => ctx.isTainted(n))) {
          ctx.report({
            node,
            message: 'Tainted input is passed to a Mongo $where filter.',
          });
        }
      },
    };
  },
};
