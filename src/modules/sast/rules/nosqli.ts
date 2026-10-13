import { calleeName } from '../ast.js';
import type { SastRule } from '../types.js';

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
        if (name === undefined || !MONGO_SINKS.has(name)) return;
        const filter = node.arguments[0];
        if (filter === undefined || filter.type === 'SpreadElement') return;
        if (!ctx.isRequestObject(filter)) return;
        ctx.report({
          node,
          message: 'req.body/req.query is passed directly into a Mongo-style filter.',
        });
      },
    };
  },
};
