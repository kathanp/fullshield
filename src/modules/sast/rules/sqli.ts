import { calleeName } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

function isSqlSink(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name === 'query' || name === 'execute';
}

export const sqliRule: SastRule = {
  meta: {
    id: 'SAST-SQLI-001',
    title: 'SQL injection via string concatenation',
    severity: 'high',
    cwe: 'CWE-89',
    docs: 'https://cwe.mitre.org/data/definitions/89.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || !isSqlSink(node)) return;
        const sql = node.arguments[0];
        if (sql !== undefined && sql.type !== 'SpreadElement' && ctx.isTainted(sql)) {
          ctx.report({
            node,
            message: 'Tainted input is concatenated into a SQL string passed to query/execute.',
          });
        }
      },
    };
  },
};
